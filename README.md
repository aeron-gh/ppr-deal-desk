# PPR Deal Desk

A private, static dashboard of every deal found in the CRM and Nikita's PPR inbox, grouped by where each one stands.

## Privacy

- All business data lives in `data/deals.enc.json`, encrypted with AES-256-GCM. The key comes from a password (PBKDF2-SHA256, 600,000 rounds).
- The password is **not** in this repo. Share it only in person or over a private channel.
- Decrypting happens in the browser. The page makes no outside requests and loads no third-party code.
- Never commit plain data files to this repo. Git keeps history, so a file pushed once stays public even after deletion.

## Turning on GitHub Pages

1. Repo **Settings → Pages**.
2. Source: **Deploy from a branch**. Branch: `main`, folder `/ (root)`. Save.
3. After a minute the site is at `https://aeron-gh.github.io/ppr-deal-desk/`.

## Using it

- **Board columns:** Your call · Team on it · Waiting on them · New in · Keep warm · Handled · Closed · Emailed, no reply.
- **Click a card** to see why it is in that column, the next action, the full email threads (newest first), CRM notes and facts.
- **Decisions:** pick Pursue, Ask team to draft a reply, Call me, Park or Pass, and add a note. Open **Decisions** at the top to copy them or send them on WhatsApp or by email.
- **Drag cards** between columns, or use **Move to** in the card. Moves, decisions and notes are saved only in that browser.
- **Checks** lists CRM cards that are out of date, unanswered replies, overdue CRM dates, unsent drafts and emails with no CRM card.
- **Lock** signs out on that device.

## Limits

- This is a snapshot, not live. The date is shown at the top right.
- Replies sent from Nikita's other outreach addresses, plus texts, calls and WhatsApp, are not visible.
- The CRM keeps no stage history here, so the board shows the current stage only.
- Estimates (asking price, EBITDA) come from broker ads or the scraper and are not verified.

## Refreshing the data

The data is rebuilt outside this repo from read-only CRM and Gmail exports, then encrypted. Only the encrypted file is committed.
