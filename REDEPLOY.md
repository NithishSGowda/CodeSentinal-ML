# Redeployment Instructions: CodeSentinel ML

This guide outlines the configuration settings required on **Render** (backend) and **Netlify** (frontend) following the repository reorganization (moving backend files into the `backend/` folder).

---

## 1. Backend Redeployment on Render

Because all backend code, libraries, and entry points have been moved into the `backend/` subdirectory, you need to update Render's path configuration.

### Configuration Settings
1. Go to your **[Render Dashboard](https://dashboard.render.com/)**.
2. Select your **codesentinal-ml** Web Service.
3. Click on the **Settings** tab in the left-hand menu.
4. Update the following fields:
   - **Root Directory**: `backend`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn server:app --bind 0.0.0.0:$PORT --timeout 120`
5. Click **Save Changes**.

### Environment Variables
Under the **Environment** tab on Render, ensure the following variables are configured:

| Key | Value | Purpose |
| :--- | :--- | :--- |
| `BREVO_API_KEY` | `<your_brevo_api_key>` | Bypasses Render's SMTP blocks to send OTP and Welcome emails over HTTPS. |
| `SMTP_EMAIL` | `techtonic202005@gmail.com` | Used as the sender address ("From:") for outgoing emails. |
| `MONGO_URI` | `mongodb+srv://nithishgowda1906_db_user:58PChYSacV82eDD7@cluster0.xukkji1.mongodb.net/` | MongoDB connection string. |
| `GEMINI_API_KEY` | `AIzaSyBmc0oxYOFdWdnxdmTXZ0uehWZblKQ5A1Y` | For AI-powered vulnerability explanation and patching. |
| `FRONTEND_URL` | `https://codesentinel-ml.netlify.app` | Redirects visitors hitting the API's root `/` URL back to your main site. |

*Note: You can safely delete the old `SMTP_PASSWORD` environment variable.*

---

## 2. Frontend Redeployment on Netlify

The frontend remains inside the `frontend/` directory, so your Netlify settings should remain unchanged, but double-check these build settings to ensure continuous deployment:

### Configuration Settings
1. Go to your **[Netlify Dashboard](https://app.netlify.com/)**.
2. Select your **codesentinel-ml** site.
3. Navigate to **Site configuration** → **Build & deploy** → **Build settings**.
4. Ensure the following values are configured:
   - **Base directory**: `frontend`
   - **Build command**: `npm run build`
   - **Publish directory**: `frontend/.next` (automatically detected if using the Next.js runtime plugin).

### Environment Variables
Under **Site configuration** → **Environment variables**, ensure you have:

| Key | Value | Purpose |
| :--- | :--- | :--- |
| `NEXT_PUBLIC_API_URL` | `https://codesentinal-ml.onrender.com` | Points your frontend dashboard to your live Render backend API. |

---

## 3. Triggering the Builds

1. **Render**: After updating the **Root Directory** in the settings, Render will automatically queue a new deployment. If it does not, click the **Manual Deploy** button in the top-right corner of the service page and select **Clear cache and deploy**.
2. **Netlify**: Since you pushed the directory changes to GitHub, Netlify will automatically trigger a new build. You can monitor the progress under the **Deploys** tab.
