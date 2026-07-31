import { render as renderBbobHtml } from "@bbob/html";
import parseBbob, { createLexer } from "@bbob/parser";
import createDOMPurify, { type Config } from "dompurify";
import {
  defineVegaPlugin,
  type VegaPlugin,
  type VegaPluginContext,
} from "@haneoka/vega/plugin";
import {
  VEGA_RICH_TEXT_SERVICE,
  type VegaRichTextHandle,
  type VegaRichTextRenderRequest,
  type VegaRichTextRenderer,
} from "@haneoka/vega-plugin-richtext";

export interface VegaBbcodeRichTextOptions {
  /**
   * Render remote HTTP(S) images. Disabled by default so story text cannot
   * silently make tracking requests.
   */
  readonly allowRemoteImages?: boolean;
  /**
   * Inputs above this limit are kept as plain text. This bounds parser work
   * without making long dialogue disappear.
   *
   * @default 262144
   */
  readonly maxInputLength?: number;
}

interface ParsedTagNode {
  readonly tag: string;
  readonly attrs: Record<string, unknown>;
  readonly content: ParsedNode | readonly ParsedNode[] | null;
  readonly end?: { readonly from: number; readonly to: number };
}

type ParsedNode = string | number | ParsedTagNode | null;

interface SafeTagNode {
  readonly tag: string;
  readonly attrs: Record<string, unknown>;
  readonly content: readonly SafeNode[] | null;
}

type SafeNode = string | SafeTagNode;

interface BbobLexerToken {
  isTag(): boolean;
  getValue(): string;
  getStart(): number;
  getEnd(): number;
}

const safeTag = (
  tag: string,
  attrs: Record<string, unknown> = {},
  content: readonly SafeNode[] | null = null,
): SafeTagNode => ({ tag, attrs, content });

const BB_TAGS = Object.freeze([
  "b",
  "i",
  "u",
  "s",
  "url",
  "img",
  "quote",
  "code",
  "div",
  "list",
  "*",
  "color",
  "size",
  "ruby",
  "br",
] as const);

const SAFE_TAGS = new Set([
  "a",
  "blockquote",
  "br",
  "cite",
  "code",
  "em",
  "font",
  "img",
  "li",
  "ol",
  "pre",
  "rb",
  "rt",
  "ruby",
  "s",
  "strong",
  "u",
  "ul",
]);

const DROPPED_TAGS = new Set([
  "audio",
  "base",
  "button",
  "canvas",
  "embed",
  "form",
  "iframe",
  "input",
  "link",
  "math",
  "meta",
  "object",
  "picture",
  "script",
  "select",
  "source",
  "style",
  "svg",
  "template",
  "textarea",
  "video",
]);

const ATTRIBUTES_BY_TAG: Readonly<Record<string, ReadonlySet<string>>> =
  Object.freeze({
    a: new Set(["href", "rel"]),
    font: new Set(["color", "size"]),
    img: new Set([
      "alt",
      "decoding",
      "loading",
      "referrerpolicy",
      "src",
    ]),
    ol: new Set(["type"]),
  });

const SAFE_URI = /^(?:(?:https?):\/\/|mailto:)/iu;
const CONTROL_OR_AMBIGUOUS_URI = /[\u0000-\u0020\u007f\\]/u;
const HTML_NAMESPACE = "http://www.w3.org/1999/xhtml";
const DEFAULT_MAX_INPUT_LENGTH = 256 * 1024;
const SELF_CLOSING_BB_TAGS = new Set(["*", "br"]);
const PAIRED_BB_TAGS = new Set<string>(
  BB_TAGS.filter((tag) => !SELF_CLOSING_BB_TAGS.has(tag)),
);

const STRICT_BBCODE_CONFIG: Config & { RETURN_DOM_FRAGMENT: true } = {
  ALLOWED_ATTR: [
    "alt",
    "color",
    "decoding",
    "href",
    "loading",
    "referrerpolicy",
    "rel",
    "size",
    "src",
    "type",
  ],
  ALLOWED_TAGS: [...SAFE_TAGS],
  ALLOWED_URI_REGEXP: SAFE_URI,
  ALLOW_ARIA_ATTR: false,
  ALLOW_DATA_ATTR: false,
  ALLOW_UNKNOWN_PROTOCOLS: false,
  FORBID_ATTR: [
    "autofocus",
    "contenteditable",
    "nonce",
    "srcdoc",
    "style",
  ],
  FORBID_TAGS: [...DROPPED_TAGS],
  KEEP_CONTENT: true,
  PARSER_MEDIA_TYPE: "text/html",
  RETURN_DOM_FRAGMENT: true,
  RETURN_TRUSTED_TYPE: false,
  SANITIZE_DOM: true,
  SANITIZE_NAMED_PROPS: true,
};

const NAMED_COLORS = new Set([
  "aqua",
  "black",
  "blue",
  "fuchsia",
  "gray",
  "green",
  "lime",
  "maroon",
  "navy",
  "olive",
  "orange",
  "purple",
  "red",
  "silver",
  "teal",
  "white",
  "yellow",
]);

const purifiers = new WeakMap<object, ReturnType<typeof createDOMPurify>>();

const asArray = (content: ParsedTagNode["content"]): ParsedNode[] => {
  if (content === null || content === undefined) return [];
  return [...(Array.isArray(content) ? content : [content])];
};

const isTagNode = (node: ParsedNode): node is ParsedTagNode =>
  typeof node === "object" &&
  node !== null &&
  typeof (node as Partial<ParsedTagNode>).tag === "string";

const escapeHtml = (value: string): string =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

const plainContent = (content: ParsedTagNode["content"]): string =>
  asArray(content)
    .map((node) => {
      if (typeof node === "string" || typeof node === "number") {
        return String(node);
      }
      return isTagNode(node) ? plainContent(node.content) : "";
    })
    .join("");

const namedAttribute = (
  node: ParsedTagNode,
  names: readonly string[],
): string | undefined => {
  const entries = Object.entries(node.attrs ?? {});
  for (const name of names) {
    const entry = entries.find(([key]) => key.toLowerCase() === name);
    if (entry && typeof entry[1] === "string") return entry[1];
  }
  return undefined;
};

const defaultAttribute = (node: ParsedTagNode): string | undefined => {
  const entries = Object.entries(node.attrs ?? {});
  const unique = entries.find(
    ([key, value]) => typeof value === "string" && key === value,
  )?.[1];
  return typeof unique === "string" ? unique : undefined;
};

const bbcodeAttribute = (
  node: ParsedTagNode,
  names: readonly string[] = [],
): string | undefined =>
  namedAttribute(node, names) ?? defaultAttribute(node);

const safeUrl = (
  raw: string | undefined,
  protocols: ReadonlySet<string>,
): string | undefined => {
  const value = raw?.trim();
  if (!value || CONTROL_OR_AMBIGUOUS_URI.test(value)) return undefined;
  try {
    const parsed = new URL(value);
    return protocols.has(parsed.protocol.toLowerCase())
      ? parsed.href
      : undefined;
  } catch {
    return undefined;
  }
};

const safeColor = (raw: string | undefined): string | undefined => {
  const value = raw?.trim().toLowerCase();
  if (!value) return undefined;
  if (NAMED_COLORS.has(value)) return value;
  return /^#(?:[\da-f]{3}|[\da-f]{4}|[\da-f]{6}|[\da-f]{8})$/u.test(
    value,
  )
    ? value
    : undefined;
};

const safeFontSize = (raw: string | undefined): string | undefined => {
  const value = raw?.trim().toLowerCase();
  if (!value) return undefined;
  const amount = Number.parseFloat(value);
  if (!Number.isFinite(amount) || amount <= 0) return undefined;
  if (/^[1-7]$/u.test(value)) return value;
  if (value.endsWith("%")) {
    if (amount <= 75) return "1";
    if (amount <= 90) return "2";
    if (amount <= 115) return "3";
    if (amount <= 140) return "4";
    if (amount <= 170) return "5";
    if (amount <= 220) return "6";
    return "7";
  }
  if (amount <= 10) return "1";
  if (amount <= 12) return "2";
  if (amount <= 16) return "3";
  if (amount <= 20) return "4";
  if (amount <= 28) return "5";
  if (amount <= 40) return "6";
  return "7";
};

const hasMalformedKnownTag = (
  nodes: readonly ParsedNode[],
  depth = 0,
): boolean => {
  if (depth > 128) return true;
  for (const node of nodes) {
    if (!isTagNode(node)) continue;
    const tag = String(node.tag).toLowerCase();
    if (tag !== "*" && tag !== "br" && !node.end) return true;
    if (hasMalformedKnownTag(asArray(node.content), depth + 1)) return true;
  }
  return false;
};

/**
 * Balance recognized BBCode before handing it to BBob.
 *
 * BBob 4.4 pairs closing tokens by stack position rather than by tag name.
 * This small recovery pass preserves its lexer and parser while making the
 * structural intent explicit:
 * - unclosed tags extend to the end of the source;
 * - a crossed close auto-closes inner tags at that boundary;
 * - unmatched closing tags are discarded as structure, never as text;
 * - code content remains context-free even when its closing tag is omitted.
 */
export const recoverBbcodeStructure = (source: string): string => {
  const input = String(source);
  const tokens = createLexer(input, {
    caseFreeTags: true,
    contextFreeTags: ["code"],
    enableEscapeTags: true,
  }).tokenize() as unknown as readonly BbobLexerToken[];
  const stack: string[] = [];
  const output: string[] = [];
  let cursor = 0;

  for (const token of tokens) {
    if (!token.isTag()) continue;
    const start = token.getStart();
    const end = token.getEnd();
    if (
      !Number.isSafeInteger(start) ||
      !Number.isSafeInteger(end) ||
      start < cursor ||
      end <= start ||
      end > input.length
    ) {
      continue;
    }

    const tokenValue = token.getValue();
    const closing = tokenValue.startsWith("/");
    const name = (closing ? tokenValue.slice(1) : tokenValue)
      .trim()
      .toLowerCase();
    if (!PAIRED_BB_TAGS.has(name) && !SELF_CLOSING_BB_TAGS.has(name)) {
      continue;
    }

    const contextFree = stack.at(-1) === "code";
    if (contextFree && !(closing && name === "code")) {
      continue;
    }

    if (!closing && SELF_CLOSING_BB_TAGS.has(name)) {
      output.push(input.slice(cursor, end));
      cursor = end;
      continue;
    }

    if (!closing) {
      output.push(input.slice(cursor, end));
      cursor = end;
      stack.push(name);
      continue;
    }

    const matchingIndex = stack.lastIndexOf(name);
    output.push(input.slice(cursor, start));
    cursor = end;
    if (matchingIndex < 0) continue;

    for (let index = stack.length - 1; index > matchingIndex; index -= 1) {
      output.push(`[/${stack[index]}]`);
    }
    output.push(input.slice(start, end));
    stack.length = matchingIndex;
  }

  output.push(input.slice(cursor));
  for (let index = stack.length - 1; index >= 0; index -= 1) {
    output.push(`[/${stack[index]}]`);
  }
  return output.join("");
};

interface TransformContext {
  readonly allowRemoteImages: boolean;
  readonly depth: number;
  readonly insideList: boolean;
}

const transformContent = (
  content: ParsedTagNode["content"],
  context: TransformContext,
): SafeNode[] =>
  asArray(content).flatMap((node) => transformNode(node, context));

const hasVisibleContent = (nodes: readonly ParsedNode[]): boolean =>
  nodes.some((node) => {
    if (typeof node === "string" || typeof node === "number") {
      return String(node).trim().length > 0;
    }
    return isTagNode(node);
  });

const transformList = (
  node: ParsedTagNode,
  context: TransformContext,
): SafeNode[] => {
  const items: ParsedNode[][] = [];
  let pending: ParsedNode[] = [];
  let sawMarker = false;

  const flush = (): void => {
    if (hasVisibleContent(pending)) items.push(pending);
    pending = [];
  };

  for (const child of asArray(node.content)) {
    if (isTagNode(child) && String(child.tag).toLowerCase() === "*") {
      flush();
      sawMarker = true;
      const ownContent = asArray(child.content);
      if (hasVisibleContent(ownContent)) items.push(ownContent);
      continue;
    }
    pending.push(child);
  }
  flush();

  if (!sawMarker || items.length === 0) {
    return transformContent(node.content, {
      ...context,
      depth: context.depth + 1,
    });
  }

  const marker = bbcodeAttribute(node)?.trim();
  const ordered = marker !== undefined && /^(?:1|a|i)$/iu.test(marker);
  const list = safeTag(
    ordered ? "ol" : "ul",
    ordered && marker && marker !== "1"
      ? { type: marker === marker.toUpperCase()
          ? marker.toUpperCase()
          : marker.toLowerCase() }
      : {},
    items.map((item) =>
      safeTag(
        "li",
        {},
        transformContent(item, {
          allowRemoteImages: context.allowRemoteImages,
          depth: context.depth + 1,
          insideList: true,
        }),
      ),
    ),
  );
  return [list];
};

const transformNode = (
  node: ParsedNode,
  context: TransformContext,
): SafeNode[] => {
  if (context.depth > 128) throw new RangeError("BBCode nesting is too deep");
  if (typeof node === "string" || typeof node === "number") {
    return [escapeHtml(String(node))];
  }
  if (!isTagNode(node)) return [];

  const tag = String(node.tag).toLowerCase();
  const next = {
    ...context,
    depth: context.depth + 1,
  };
  const children = (): SafeNode[] => transformContent(node.content, next);

  switch (tag) {
    case "b":
      return [safeTag("strong", {}, children())];
    case "i":
      return [safeTag("em", {}, children())];
    case "u":
      return [safeTag("u", {}, children())];
    case "s":
      return [safeTag("s", {}, children())];
    case "quote": {
      const attribution = bbcodeAttribute(node, ["author"]);
      return [
        safeTag("blockquote", {}, [
          ...(attribution
            ? [safeTag("cite", {}, [escapeHtml(attribution)])]
            : []),
          ...children(),
        ]),
      ];
    }
    case "code":
      return [
        safeTag("pre", {}, [
          safeTag("code", {}, [escapeHtml(plainContent(node.content))]),
        ]),
      ];
    case "url": {
      const href = safeUrl(
        bbcodeAttribute(node, ["href", "url"]) ??
          plainContent(node.content),
        new Set(["http:", "https:", "mailto:"]),
      );
      const content = children();
      if (!href) return content;
      return [
        safeTag(
          "a",
          { href, rel: "noopener noreferrer" },
          content.length ? content : [escapeHtml(href)],
        ),
      ];
    }
    case "img": {
      const rawSource =
        bbcodeAttribute(node, ["src"]) ?? plainContent(node.content);
      const source = safeUrl(rawSource, new Set(["http:", "https:"]));
      if (!context.allowRemoteImages || !source) {
        const fallback = plainContent(node.content) || rawSource || "";
        return fallback ? [escapeHtml(fallback)] : [];
      }
      return [
        safeTag(
          "img",
          {
            src: source,
            alt: namedAttribute(node, ["alt"]) ?? "",
            loading: "lazy",
            decoding: "async",
            referrerpolicy: "no-referrer",
          },
          null,
        ),
      ];
    }
    case "list":
      return transformList(node, context);
    case "*":
      return context.insideList
        ? [safeTag("li", {}, children())]
        : [escapeHtml("[*]"), ...children()];
    case "color": {
      const color = safeColor(bbcodeAttribute(node, ["color"]));
      return color
        ? [safeTag("font", { color }, children())]
        : children();
    }
    case "size": {
      const size = safeFontSize(bbcodeAttribute(node, ["size"]));
      return size
        ? [safeTag("font", { size }, children())]
        : children();
    }
    case "ruby": {
      const annotation = bbcodeAttribute(node, ["ruby", "rt"]);
      if (!annotation) return children();
      return [
        safeTag("ruby", {}, [
          safeTag("rb", {}, children()),
          safeTag("rt", {}, [escapeHtml(annotation)]),
        ]),
      ];
    }
    case "br":
      return [safeTag("br", {}, null)];
    default:
      return children();
  }
};

const purifierFor = (
  document: Document,
): ReturnType<typeof createDOMPurify> | undefined => {
  const view = document.defaultView;
  if (!view) return undefined;
  const key = view as unknown as object;
  const cached = purifiers.get(key);
  if (cached) return cached;
  const purifier = createDOMPurify(view);
  purifiers.set(key, purifier);
  return purifier;
};

const removeUnsafeNodesAndAttributes = (
  fragment: DocumentFragment,
  allowRemoteImages: boolean,
): DocumentFragment => {
  const clean = (node: Node): void => {
    if (node.nodeType === 8) {
      node.parentNode?.removeChild(node);
      return;
    }
    if (node.nodeType !== 1) {
      if (node.nodeType !== 3) node.parentNode?.removeChild(node);
      return;
    }

    const element = node as Element;
    const tag = element.localName.toLowerCase();
    if (
      element.namespaceURI !== HTML_NAMESPACE ||
      !SAFE_TAGS.has(tag) ||
      (tag === "img" && !allowRemoteImages)
    ) {
      if (
        element.namespaceURI !== HTML_NAMESPACE ||
        DROPPED_TAGS.has(tag) ||
        tag === "img"
      ) {
        element.remove();
        return;
      }
      for (const child of [...element.childNodes]) clean(child);
      element.replaceWith(...element.childNodes);
      return;
    }

    const allowed = ATTRIBUTES_BY_TAG[tag] ?? new Set<string>();
    for (const attribute of [...element.attributes]) {
      if (!allowed.has(attribute.name.toLowerCase())) {
        element.removeAttribute(attribute.name);
      }
    }
    if (tag === "a") {
      const href = safeUrl(
        element.getAttribute("href") ?? undefined,
        new Set(["http:", "https:", "mailto:"]),
      );
      if (href) element.setAttribute("href", href);
      else element.removeAttribute("href");
    }
    if (tag === "img") {
      const source = safeUrl(
        element.getAttribute("src") ?? undefined,
        new Set(["http:", "https:"]),
      );
      if (!source) {
        element.remove();
        return;
      }
      element.setAttribute("src", source);
    }
    for (const child of [...element.childNodes]) clean(child);
  };

  for (const child of [...fragment.childNodes]) clean(child);
  return fragment;
};

const plainFragment = (
  document: Document,
  source: string,
): DocumentFragment => {
  const fragment = document.createDocumentFragment();
  fragment.append(document.createTextNode(source));
  return fragment;
};

/**
 * Parse and sanitize BBCode without ever sacrificing readable source text.
 *
 * Unknown, structurally malformed, excessively nested, or oversized input is
 * returned as inert plain text. BBob is intentionally limited to the supported
 * tag set before its tree is converted to HTML.
 */
export const renderBbcodeToFragment = (
  document: Document,
  source: string,
  options: VegaBbcodeRichTextOptions = {},
): DocumentFragment => {
  const input = String(source);
  const maxInputLength = options.maxInputLength ?? DEFAULT_MAX_INPUT_LENGTH;
  if (
    !Number.isSafeInteger(maxInputLength) ||
    maxInputLength < 1 ||
    input.length > maxInputLength
  ) {
    return plainFragment(document, input);
  }

  try {
    let parserError = false;
    const recovered = recoverBbcodeStructure(input);
    const parsed = parseBbob(recovered, {
      caseFreeTags: true,
      contextFreeTags: ["code"],
      enableEscapeTags: true,
      onlyAllowTags: [...BB_TAGS],
      onError: () => {
        parserError = true;
      },
    }) as unknown as ParsedNode[];
    if (parserError || hasMalformedKnownTag(parsed)) {
      return plainFragment(document, input);
    }
    const safeTree = parsed.flatMap((node) =>
      transformNode(node, {
        allowRemoteImages: options.allowRemoteImages ?? false,
        depth: 0,
        insideList: false,
      }),
    );
    // BBob's 4.4.1 declaration emits optional position fields as explicit
    // `undefined`, which is incompatible with exactOptionalPropertyTypes even
    // though the renderer only reads this structural tag/content tree.
    const markup = renderBbobHtml(
      safeTree as unknown as Parameters<typeof renderBbobHtml>[0],
    );
    const purifier = purifierFor(document);
    if (!purifier) return plainFragment(document, input);
    // A neutral root also protects the first text/formatting node from
    // DOM-emulator traversal quirks; it is removed before the result escapes.
    const sanitized = purifier.sanitize(
      `<div>${markup}</div>`,
      STRICT_BBCODE_CONFIG,
    );
    if (sanitized.nodeType !== 11) return plainFragment(document, input);
    const owned = sanitized.ownerDocument === document
      ? sanitized
      : document.importNode(sanitized, true);
    return removeUnsafeNodesAndAttributes(
      owned,
      options.allowRemoteImages ?? false,
    );
  } catch {
    return plainFragment(document, input);
  }
};

export const createVegaBbcodeRichTextRenderer = (
  options: VegaBbcodeRichTextOptions = {},
): VegaRichTextRenderer =>
  Object.freeze({
    id: "vega-bbcode",
    formats: ["bbcode", "bb"],
    render({ document, signal, source }: VegaRichTextRenderRequest) {
      if (signal.aborted) return document.createDocumentFragment();
      return renderBbcodeToFragment(document, source, options);
    },
  });

export const vegaBbcodeRichTextRenderer =
  createVegaBbcodeRichTextRenderer();

const registerRenderer = (
  context: VegaPluginContext,
  renderer: VegaRichTextRenderer,
): VegaRichTextHandle => {
  const service = context.service(VEGA_RICH_TEXT_SERVICE);
  if (!service) {
    throw new ReferenceError(
      "Vega BBCode rich text requires haneoka.vega-richtext",
    );
  }
  return service.register(renderer);
};

export const createVegaBbcodeRichTextPlugin = (
  options: VegaBbcodeRichTextOptions = {},
): VegaPlugin =>
  defineVegaPlugin({
    manifest: {
      id: "haneoka.vega-richtext-bbcode",
      name: "Vega Rich Text BBCode",
      version: "0.1.0",
      apiVersion: 1,
      description:
        "Fault-tolerant BBCode rendering with strict active-content filtering",
      capabilities: ["rich-text"],
      dependencies: {
        "haneoka.vega-richtext": "^0.1.0",
      },
    },
    setup(context) {
      const registration = registerRenderer(
        context,
        createVegaBbcodeRichTextRenderer(options),
      );
      return { dispose: () => registration.dispose() };
    },
  });

export const vegaBbcodeRichTextPlugin =
  createVegaBbcodeRichTextPlugin();

export default vegaBbcodeRichTextPlugin;
