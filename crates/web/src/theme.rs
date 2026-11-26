//! The light/dark theme. `static/theme.js` owns it (storage key, the user's
//! choice else the system's, following live system changes): index.html runs
//! it before the first paint, and the header toggle calls into it here.

use wasm_bindgen::prelude::{JsValue, wasm_bindgen};

#[wasm_bindgen(js_namespace = tunnelTheme)]
extern "C" {
    #[wasm_bindgen(catch, js_name = choice)]
    fn js_choice() -> Result<String, JsValue>;
    #[wasm_bindgen(catch, js_name = set)]
    fn js_set(theme: &str) -> Result<(), JsValue>;
}

/// The user's choice: "light", "dark" or "system" (also when theme.js did
/// not load; the CSS then follows the system on its own).
pub fn choice() -> String {
    js_choice().unwrap_or_else(|_| "system".into())
}

/// Stores a choice and applies it.
pub fn set(theme: &str) {
    let _ = js_set(theme);
}

#[cfg(test)]
mod tests {
    //! Checks on the style sheets as written, with the browser's colour maths
    //! (OKLCH to sRGB, alpha compositing in sRGB, WCAG contrast).
    use std::collections::HashMap;

    const TOKENS: &str = include_str!("../style/tokens.css");
    const APP: &str = include_str!("../style/app.css");
    const THEME_JS: &str = include_str!("../static/theme.js");

    /// Custom properties in the light (`:root`) and dark (`.dark`, on the
    /// same root element, so it inherits the rest) themes.
    fn tokens() -> [HashMap<&'static str, &'static str>; 2] {
        let (mut light, mut dark) = (HashMap::new(), HashMap::new());
        let mut block = None;
        for line in TOKENS.lines() {
            match line {
                ":root {" | ".dark {" => block = Some(line == ".dark {"),
                "}" => block = None,
                _ => {
                    let decl = line.trim().strip_prefix("--").and_then(|d| d.split_once(": "));
                    if let (Some(is_dark), Some((name, value))) = (block, decl) {
                        let value = value.trim_end_matches(';');
                        (if is_dark { &mut dark } else { &mut light }).insert(name, value);
                    }
                }
            }
        }
        let dark = light.clone().into_iter().chain(dark).collect();
        [light, dark]
    }

    /// sRGB (0..1) and alpha.
    type Rgba = ([f64; 3], f64);

    fn resolve(tokens: &HashMap<&str, &str>, value: &str) -> Rgba {
        let value = value.trim();
        if let Some(name) = value.strip_prefix("var(--").and_then(|v| v.strip_suffix(')')) {
            return resolve(tokens, tokens.get(name).unwrap_or_else(|| panic!("no token --{name}")));
        }
        if let Some(args) = value.strip_prefix("color-mix(in oklch, ").and_then(|v| v.strip_suffix(", transparent)")) {
            let (color, pct) = args.rsplit_once(' ').expect("color and percentage");
            let (rgb, alpha) = resolve(tokens, color);
            return (rgb, alpha * pct.trim_end_matches('%').parse::<f64>().unwrap() / 100.0);
        }
        let args = value.strip_prefix("oklch(").and_then(|v| v.strip_suffix(')')).unwrap_or_else(|| panic!("{value}"));
        let number =
            |a: &str| a.strip_suffix('%').map_or_else(|| a.parse().unwrap(), |p| p.parse::<f64>().unwrap() / 100.0);
        let (lch, alpha) = args.split_once(" / ").map_or((args, 1.0), |(c, a)| (c, number(a)));
        let n: Vec<f64> = lch.split(' ').map(|x| x.parse().unwrap()).collect();
        (oklch_to_srgb(n[0], n[1], n[2]), alpha)
    }

    fn oklch_to_srgb(l: f64, c: f64, h: f64) -> [f64; 3] {
        let (a, b) = (c * h.to_radians().cos(), c * h.to_radians().sin());
        let l_ = (l + 0.396_337_777_4 * a + 0.215_803_757_3 * b).powi(3);
        let m_ = (l - 0.105_561_345_8 * a - 0.063_854_172_8 * b).powi(3);
        let s_ = (l - 0.089_484_177_5 * a - 1.291_485_548 * b).powi(3);
        let linear = [
            4.076_741_662_1 * l_ - 3.307_711_591_3 * m_ + 0.230_969_929_2 * s_,
            -1.268_438_004_6 * l_ + 2.609_757_401_1 * m_ - 0.341_319_396_5 * s_,
            -0.004_196_086_3 * l_ - 0.703_418_614_7 * m_ + 1.707_614_701 * s_,
        ];
        // Out-of-gamut channels are clipped, as Chromium renders them.
        linear.map(|x| {
            let x = x.clamp(0.0, 1.0);
            if x <= 0.003_130_8 { 12.92 * x } else { 1.055 * x.powf(1.0 / 2.4) - 0.055 }
        })
    }

    fn over((top, alpha): Rgba, under: [f64; 3]) -> [f64; 3] {
        [0, 1, 2].map(|i| top[i] * alpha + under[i] * (1.0 - alpha))
    }

    fn contrast(x: [f64; 3], y: [f64; 3]) -> f64 {
        let lum = |c: [f64; 3]| {
            let f = |v: f64| if v <= 0.040_45 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) };
            0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2])
        };
        let (a, b) = (lum(x), lum(y));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    #[test]
    fn state_badges_and_alerts_are_readable_in_both_themes() {
        let mut checked = 0;
        for line in APP.lines().filter(|l| l.starts_with(".badge-") || l.starts_with(".alert-")) {
            let (selector, body) = line.split_once(" { ").unwrap();
            let decls: HashMap<&str, &str> =
                body.trim_end_matches(" }").split(';').filter_map(|d| d.trim().split_once(": ")).collect();
            let (Some(color), Some(background)) = (decls.get("color"), decls.get("background")) else { continue };
            for (theme, tokens) in ["light", "dark"].iter().zip(tokens()) {
                let text = resolve(&tokens, color);
                assert_eq!(text.1, 1.0, "{selector} text is opaque");
                for surface in ["background", "card"] {
                    let under = resolve(&tokens, &format!("var(--{surface})"));
                    let ratio = contrast(text.0, over(resolve(&tokens, background), under.0));
                    assert!(ratio >= 4.5, "{selector} on --{surface} in {theme}: {ratio:.2}:1");
                }
            }
            checked += 1;
        }
        assert!(checked >= 7, "found only {checked} state rules in app.css");
    }

    #[test]
    fn the_first_paint_background_is_the_background_token() {
        let line =
            THEME_JS.lines().find(|l| l.contains("style.backgroundColor")).expect("theme.js sets the background");
        let (_, choice) = line.split_once("dark ? ").unwrap();
        let (dark, light) = choice.trim_end_matches(';').split_once(" : ").unwrap();
        let [light_tokens, dark_tokens] = tokens();
        assert_eq!(light.trim_matches('"'), light_tokens["background"]);
        assert_eq!(dark.trim_matches('"'), dark_tokens["background"]);
    }
}
