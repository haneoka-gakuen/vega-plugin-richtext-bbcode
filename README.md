# Vega Rich Text BBCode

Fault-tolerant BBCode rendering for [Vega](https://github.com/haneoka-gakuen/vega).

The plugin registers the `bbcode` and `bb` formats with
`@haneoka/vega-plugin-richtext`. Without this plugin, the same inputs remain
plain text in both inline and display rendering modes.

## Supported tags

`b`, `i`, `u`, `s`, `url`, `img`, `quote`, `code`, `list`, `*`, `color`,
`size`, `ruby`, and `br`.

Tags are case-insensitive. Unknown or structurally malformed markup stays
readable instead of swallowing later dialogue. Recoverable unclosed tags are
balanced at the end of the input, while crossed tags are closed at the nearest
matching boundary.

## Usage

```ts
import { VegaPluginHost } from "@haneoka/vega/plugin";
import { createVegaRichTextPlugin } from "@haneoka/vega-plugin-richtext";
import {
  createVegaBbcodeRichTextPlugin,
} from "@haneoka/vega-plugin-richtext-bbcode";

const host = new VegaPluginHost();
await host.install(createVegaRichTextPlugin());
await host.install(createVegaBbcodeRichTextPlugin());
```

Remote images are disabled by default. Enable them explicitly when the story
source is trusted:

```ts
createVegaBbcodeRichTextPlugin({ allowRemoteImages: true });
```

Only HTTP(S) image URLs are accepted. Links are limited to HTTP(S) and
`mailto:`. Generated HTML is strictly sanitized; scripts, embedded content,
inline styles, event handlers, `javascript:` URLs, and `data:` URLs are not
rendered.

## License

MPL-2.0.
