# Auth + CAPTCHA + Google/Facebook OAuth (Demo)

## Run in VS Code
1) Open folder `auth-notify-project` in VS Code  
2) Create env file:
   - Copy `server/.env.example` -> `server/.env`
   - Fill keys (reCAPTCHA + Google/Facebook OAuth)
3) Install & run:
```bash
cd server
npm install
npm start
```
4) Open:
- http://localhost:3000/login.html

## Notes
- `public/login.html` has `YOUR_RECAPTCHA_SITE_KEY` placeholder. Replace with your **reCAPTCHA site key**.
- If you don't want OAuth now, you can still use email+password register/login (but CAPTCHA still required for register).
