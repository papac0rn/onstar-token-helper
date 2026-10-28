# OnStar Token Helper

**Website:** https://papac0rn.github.io/onstar-token-helper/ · **Step-by-step guide with screenshots:** [Wiki](https://github.com/papac0rn/onstar-token-helper/wiki/Walkthrough)

A one-click Windows tool that gets the [BigThunderSR OnStar2MQTT Home Assistant add-on](https://github.com/BigThunderSR/homeassistant-addons-onstar2mqtt) working again when its automated GM sign-in is blocked:

```
🚫 Access Denied: GM's auth server blocked this sign-in attempt.
```

It does the same job as the add-on docs' manual "Firefox token procedure", plus installing the token, without the copying by hand:

1. Opens GM's real sign-in page in **your normal browser**. You sign in yourself, so GM's bot detection sees a person. **The tool never sees your GM password.**
2. Catches GM's `msauth.com.gm.mychevrolet://auth?code=…` redirect. The tool registers itself as that link's handler for the current Windows user.
3. Trades the one-time code for a token set (OAuth PKCE), the same way [metheos/onstar_firefox](https://github.com/metheos/onstar_firefox) does.
4. Hands the token to Home Assistant's built-in **Downloader** integration. The file is served once, to your HA's IP only, from a random URL. HA saves it as `/share/<folder>/microsoft_tokens.json`.
5. Starts the add-on and checks it stays running for 2 minutes. If it rejects the token, it exits after one try, and the tool turns off start-on-boot so it won't keep retrying and make GM's block worse.

The token stays in memory on your PC and is never written to its disk.

## Requirements

- Windows 10/11, Python 3.10+ with Tk (the python.org installer includes it)
- `pip install websockets`
- Home Assistant OS / Supervised with the OnStar2MQTT add-on
- An HA **long-lived access token** from an admin user: HA → your profile → Security → Long-lived access tokens

## First run

1. Double-click `onstar_token_helper.pyw`.
2. Enter your HA address (e.g. `http://192.168.x.x`) and the long-lived token. They're stored in `%LOCALAPPDATA%\OnStarTokenHelper\settings.json`, with the token encrypted by Windows DPAPI (only your Windows user can read it).
3. Click **Sign in to GM and fix the add-on**. The first run may ask you to:
   - **Moves the add-on token folder** (automatic): sets `TOKEN_LOCATION` to `/share/vehicle1`, because Home Assistant can save files into `/share` but not into `/ssl`. Other add-on settings are left unchanged.
   - **Allow a firewall rule** (a Windows admin prompt). It lets *only* your HA box reach port 8766 on this PC.
   - **Set up Downloader.** The tool does this itself, pointing it at `/share`.
4. Sign in to GM in the browser tab. When the browser asks to open the helper (or `pythonw`), allow it.
5. Confirm the account shown matches the add-on's `ONSTAR_USERNAME`.

The token renews itself in the add-on. If GM blocks it again later, run the tool again.

## Notes

- Use the same GM account as the add-on. If the account differs, the add-on ignores the token and tries its own sign-in, which the tool detects and stops.
- `ONSTAR_TOTP` should still be set in the add-on, as the add-on docs say.
- Unofficial; not affiliated with GM/OnStar. Uses the public client ID of GM's mobile app, as OnStarJS does.

## Credits

- [metheos/onstar_firefox](https://github.com/metheos/onstar_firefox): the PKCE capture approach
- [BigThunderSR/OnStarJS](https://github.com/BigThunderSR/OnStarJS) and [onstar2mqtt add-on](https://github.com/BigThunderSR/homeassistant-addons-onstar2mqtt)

## License

MIT
