# 📚 NCERT Reader (Flask + React)

This repository now provides a **mobile-first NCERT reading app**.
The React frontend is converted from the previous blog UI to an installable PWA that reads books from a GitHub-hosted catalog.

## What it does

- Browse NCERT content by **class → subject → book → chapter**
- Open chapter content in an in-app reader (PDF/HTML)
- Save **continue reading** and **bookmarks** in local storage
- Cache catalog/content for lower-bandwidth usage
- Install to phone home screen (Android/iOS PWA behavior)

## Catalog source

The reader expects a hosted catalog JSON, configured by:

- `REACT_APP_NCERT_CATALOG_URL`

If this variable is not set, the app falls back to a bundled sample catalog.

### Catalog shape

```json
{
  "classes": [
    {
      "id": "class-10",
      "name": "Class 10",
      "subjects": [
        {
          "id": "science",
          "name": "Science",
          "books": [
            {
              "id": "science-10",
              "title": "NCERT Science",
              "description": "Optional",
              "chapters": [
                {
                  "id": "chapter-1",
                  "title": "Chemical Reactions",
                  "type": "pdf",
                  "url": "https://..."
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

## Run locally

### Backend (optional for this reader UI)

```bash
pip install -r requirements.txt
python app.py
```

### Frontend

```bash
cd frontend
npm install
npm start
```

## Build

```bash
cd frontend
npm run build
```

## Mobile install testing

- Android Chrome: open app → browser menu → **Install app**
- iOS Safari: open app → Share → **Add to Home Screen**

## Notes

- The existing Flask backend remains in this repository.
- Primary work for this task is in the React frontend.
