import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import smtplib
from flask import Flask

from app import create_app, db, send_email


def make_mail_app(**config):
    app = Flask(__name__)
    app.config.update(config)
    return app


class SendEmailTest(unittest.TestCase):
    def test_returns_error_when_smtp_not_configured(self):
        app = make_mail_app(MAIL_SERVER='', MAIL_USERNAME='')
        result = send_email(app, 'user@example.com', 'Subject', '<p>Hi</p>')
        self.assertIsInstance(result, tuple)
        ok, error = result
        self.assertFalse(ok)
        self.assertIn('SMTP not configured', error)

    @patch('app.smtplib.SMTP')
    def test_returns_success_when_smtp_sends(self, mock_smtp):
        mock_smtp.return_value.__enter__.return_value = MagicMock()
        app = make_mail_app(
            MAIL_SERVER='smtp.example.com',
            MAIL_PORT=587,
            MAIL_USERNAME='mailer@example.com',
            MAIL_PASSWORD='secret',
            MAIL_SENDER='noreply@example.com',
            MAIL_USE_TLS=True,
        )
        ok, error = send_email(app, 'user@example.com', 'Subject', '<p>Hi</p>')
        self.assertTrue(ok)
        self.assertIsNone(error)

    @patch('app.smtplib.SMTP')
    def test_returns_smtp_error_message_on_auth_failure(self, mock_smtp):
        mock_server = MagicMock()
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(535, b'auth failed')
        mock_smtp.return_value.__enter__.return_value = mock_server
        app = make_mail_app(
            MAIL_SERVER='smtp.example.com',
            MAIL_PORT=587,
            MAIL_USERNAME='mailer@example.com',
            MAIL_PASSWORD='wrong',
            MAIL_USE_TLS=True,
        )
        ok, error = send_email(app, 'user@example.com', 'Subject', '<p>Hi</p>')
        self.assertFalse(ok)
        self.assertIn('SMTPAuthenticationError', error)
        self.assertIn('auth failed', error)


class AdminTestMailPageTest(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.app = create_app({
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': f'sqlite:///{self.db_path}',
            'SECRET_KEY': 'test-secret',
            'ADMIN_USERNAME': 'admin',
            'ADMIN_PASSWORD': 'admin123',
            'MAIL_SERVER': 'smtp.example.com',
            'MAIL_PORT': 587,
            'MAIL_USERNAME': 'mailer@example.com',
            'MAIL_PASSWORD': 'secret',
            'MAIL_SENDER': 'noreply@example.com',
            'MAIL_USE_TLS': True,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def login(self):
        return self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin123',
        }, follow_redirects=True)

    def test_test_mail_page_requires_login(self):
        response = self.client.get('/admin/test-mail')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers['Location'])

    def test_test_mail_page_shows_form_and_smtp_config(self):
        self.login()
        response = self.client.get('/admin/test-mail')
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('smtp.example.com', body)
        self.assertIn('mailer@example.com', body)
        self.assertIn('name="email"', body)
        self.assertNotIn('secret', body)

    @patch('app.smtplib.SMTP')
    def test_test_mail_page_shows_success(self, mock_smtp):
        mock_smtp.return_value.__enter__.return_value = MagicMock()
        self.login()
        response = self.client.post('/admin/test-mail', data={
            'email': 'you@example.com',
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('Test email sent', body)
        self.assertIn('you@example.com', body)

    @patch('app.smtplib.SMTP')
    def test_test_mail_page_shows_error_message(self, mock_smtp):
        mock_server = MagicMock()
        mock_server.starttls.side_effect = smtplib.SMTPException('connection timed out')
        mock_smtp.return_value.__enter__.return_value = mock_server
        self.login()
        response = self.client.post('/admin/test-mail', data={
            'email': 'you@example.com',
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('connection timed out', body)


if __name__ == '__main__':
    unittest.main()

