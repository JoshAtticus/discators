# Discators

Discators is a web application that allows you to track views on your Discord messages using invisible 1x1 pixel images.

## Features

- **Create Discators**: Generate unique, invisible 1x1 pixel images
- **Message Confirmation**: Know when your message was sent (first view)
- **View Tracking**: Count how many times your message has been viewed
- **User Accounts**: Secure registration and login system
- **Dark Mode**: Discord-inspired dark theme with blurple accents

## How It Works

Discators works by embedding invisible 1x1 pixel images in your Discord messages. When Discord loads the image, our server records the view. The first view indicates when the message was successfully sent, and subsequent views count as message views.

## Installation

1. Clone this repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the application:
   ```
   python app.py
   ```

## Usage

1. Register for an account
2. Create a new discator with a descriptive name
3. Copy the discator URL
4. Paste the URL in your Discord message
5. View statistics in your dashboard

## Technologies Used

- **Backend**: Flask, SQLAlchemy
- **Frontend**: HTML, CSS, JavaScript
- **Database**: SQLite
- **Styling**: Bootstrap 5 with custom dark theme
- **Image Generation**: Pillow (Python Imaging Library)

## License

MIT

---

Created for tracking Discord message views without disrupting the user experience.