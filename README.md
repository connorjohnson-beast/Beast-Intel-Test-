# Beast Intel — automatic online monitoring, at no cost

## What this actually is

A dashboard that checks the internet for mentions of MrBeast, Feastables,
and Beast Industries — on its own, every 6 hours, forever — and shows you
what it found, sorted by how serious it looks. You don't run any searches
by hand. You just open the dashboard and read what's already there.

It costs **$0/month**. Not "free tier that runs out" — genuinely free,
because it only uses services that are free by design: public news feeds,
and a free automation service (GitHub Actions) that every GitHub account
gets a large monthly allowance of, more than this will ever use.

## What it checks right now

- **Google News** and **Bing News** — real news coverage, the moment it's published.
- **Hacker News** — where tech-community chatter (including leaks, breaches, scam warnings) tends to surface first.

Each result gets sorted into one of five buckets automatically — threats,
leaked personal info, fake/impersonation accounts, financial/legal, or
general negative coverage — and given a severity so the worst stuff is
easy to spot at a glance.

## How to make it run itself, forever, for free

Three steps, one time only:

1. **Put this folder on GitHub.** Create a free GitHub account if you don't
   have one, create a new repository, and upload everything in this folder
   to it (drag-and-drop works — GitHub's website lets you upload a folder
   directly, no command line needed).
2. **Turn on Actions.** On your new repository's page, click the
   **Actions** tab, and click the green button to enable workflows. That's
   it — the schedule in this folder tells it to run every 6 hours by itself
   from that point on.
3. **Turn on GitHub Pages** (optional, but this is what makes it a real
   website instead of a file you download). In the repository's
   **Settings → Pages**, set it to publish from the main branch. GitHub
   will give you a real web address — open that any time to see the
   latest sweep, from any device, without downloading anything.

That's the whole setup. After this, nobody has to remember to run anything.

## The one file you're allowed to edit

**`config.json`** — this is the only file meant for a human to touch.
Open it, and you'll see two lists:

- `watch_terms` — the names/brands being watched. Add or remove entries here.
- `risk_modifiers` — words that, combined with a watch term, flag something
  as worth a closer look (scam, lawsuit, leak, etc.). Add more if you think
  of other warning words.

Save the file, and the next scheduled run picks up the change automatically.

## Running it yourself right now, without waiting

If you want to see it update immediately instead of waiting for the next
scheduled run: open the repository on GitHub, click **Actions**, click
**Beast Intel Sweep**, then click **Run workflow**. It finishes in under a
minute.

You can also run it on your own computer if Python is installed:
```
python3 fetch_intel.py
```
Then open `dashboard.html` in a browser.

## What's in this folder

| File | What it's for |
|---|---|
| `fetch_intel.py` | The actual checking logic — this is what runs every 6 hours |
| `config.json` | The names/brands to watch — the only file you should edit |
| `dashboard_template.html` | The dashboard's design — leave this alone |
| `dashboard.html` | **Open this one.** Gets rewritten with fresh results every run |
| `live_findings.json` | The same results, as raw data, if you ever need to plug this into something else |
| `.github/workflows/scan.yml` | The schedule — tells GitHub to run this every 6 hours, for free |

## Honest limitations, stated plainly

- This checks public news and Hacker News. It does **not** check X/Twitter,
  Instagram, TikTok, or Reddit — those platforms don't allow free automatic
  checking anymore. Those still need a person to search them by hand
  occasionally (the manual search tool covers this).
- The category/severity labels are automatic guesses based on keywords, not
  a person's judgment. Treat "Critical" as "look at this first," not as a
  confirmed emergency — always have a person confirm before acting on
  anything serious.
- It only reports something once. If a story is still developing, you're
  seeing the first sighting of it, not a live tracker of that one story.
