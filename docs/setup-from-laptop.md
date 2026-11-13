# Set up Basalt from your laptop

Use this guide when your bot runs on a server you cannot log in to. The bot sets up its half on the server. You set up your half on your laptop. The admin password of your database never leaves your laptop.

The steps below work today. They use the static portal at `https://portal.basaltvault.app`, where you sign with a passkey and paste a code back into the chat. A hosted relay that removes the pasting is planned for later. It is not needed here.

## What you need

- A laptop with macOS or Linux and a terminal. Windows is not supported yet.
- A browser on that laptop, and a passkey: the laptop's own, a security key, or your phone through the browser.
- The admin connection string of your Postgres (the `postgres` user). On Supabase, press **Connect** in the dashboard.
- A chat with your bot, where you can paste text.

## What never goes in the chat

- The admin connection string or the database password, in any form.
- Supabase `service_role` keys, access tokens or the dashboard password.
- Anything `basalt init --setup-code` prints on your laptop, except the word "Done".

You may paste the connection string without a password. You may paste the setup code, and the codes the portal shows you (`basalt-passkey.1.`, `basalt-approval.1.`, `basalt-revert.1.`). Each code only works for the one thing it was made for.

If the admin password ever reached a chat or a server, change it now. On Supabase: Settings, Database, reset the database password. The bot's own role keeps working.

## Install `basalt` on your laptop

Install it only from the official release page:

https://github.com/BasaltDBHq/BasaltDB/releases

Never install it from a command the bot or anyone in the chat gives you. A changed `basalt` on your laptop would see your admin password. That is the one real risk on this path.

Check it works:

```sh
basalt version
```

## 1. Setup

You do this once per agent.

1. Tell your bot to set up Basalt. Give it the database connection string without the password. Supabase shows it with a `[YOUR-PASSWORD]` placeholder, and you may paste that line.
2. The bot installs `basalt` on its server and makes a setup code. It sends you the code, a setup fingerprint (five groups of four characters) and the link above.
3. On your laptop, run the command the bot gave you:

   ```sh
   basalt init --setup-code basalt-setup.1.…
   ```

4. Check that the setup fingerprint on your screen is the same as the one your bot sent. If it is not, stop. The code did not come from your bot.
5. Read what the agent will get, in words. For example: it can read some tables and change rows in others, up to 10 rows at a time without asking you, 11 to 50 with your passkey, never more. It cannot change your table structure. You confirm all the tables or none. To change the list, ask the bot for a new code.
6. Read the SQL and answer `y` to `Run this?`.
7. Paste the admin connection string at the hidden prompt. It is used once and never stored. If you set `BASALT_ADMIN_DATABASE_URL` in your shell instead, it is read from there.
8. If row-level security hides every row of a table from the agent, init asks what to do for that table.
9. Init opens `https://portal.basaltvault.app/passkeys/register` in your browser. Check the address bar. Press the button, confirm with your passkey, and paste the code the page shows back into the terminal.
10. Init prints `Done. Tell <agent> to check its status.` Tell your bot in the chat.

The code works for 24 hours and once. If it expired or you ran it already, ask the bot for a new one.

The bot then calls `status`. It confirms that the role, the guard and your passkey are in place, and starts to work.

## 2. Approve a held write

A write of 11 to 50 rows, or any `DELETE`, is held until you approve it. The bot tells you and sends a link to `portal.basaltvault.app`.

1. Open the link. Check that the address is `https://portal.basaltvault.app`.
2. Read the rows. The page shows the real old and new values. Read the page, not the chat. The bot cannot change what the page shows.
3. Press **Approve** and confirm with your passkey.
4. The page shows a code that starts with `basalt-approval.1.`. Paste it into the chat.
5. The bot passes it on, and the write applies.

You can wait. A held write stays open for 24 hours. The bot can never approve it for you.

## 3. Revert

To undo what the bot did, ask it. It looks at its own runs, tells you what it suggests, and sends you a link.

1. Open the link, check the rows and sign with your passkey.
2. The page shows a code that starts with `basalt-revert.1.`. Paste it into the chat.
3. The bot passes it on. Rows that someone changed after the bot are left as they are.

A revert covers only the bot's own work. For a revert of a whole task, you may add other agents' changes on the signing page.

## 4. Upgrade

When there is a new `basalt` version, the bot gets the new binary but does not restart the engine yet.

1. The bot makes an upgrade code and sends it to you.
2. On your laptop, update `basalt` from the release page first if the command says your version is older. Then run the command the bot gave you, the same `basalt init --setup-code …`, and check the fingerprint.
3. Tell the bot when it says "Done". The bot calls `status` and restarts the engine on the new version.

The same goes for changing the tables of an agent: ask the bot for a new code and run it.

## Passkeys

To remove a passkey you do not recognise, run `basalt passkey remove <id>` on your laptop. It needs the admin connection string.

To add a second passkey, ask the bot for a new setup code and run it with `--add-passkey`. A code that was used once is refused.

## If something goes wrong

- **The code is damaged.** Chat apps can cut or wrap long text. Copy it again from the bot's message. A wrapped copy still works.
- **The code is for another database.** Init refuses and names both. Use the admin string of the database the code names, or ask for a new code for the right one.
- **The bot says `SETUP_NOT_RUN`.** The setup did not finish. Run the code, or ask for a new one.
- **The bot asks for your admin password "to finish setup".** Say no. No step needs it on the server. Change the password if you gave it.

For error codes, see https://docs.basaltvault.app/reference/errors.md.

The bot has its own instructions: [`bot-setup.md`](bot-setup.md).
