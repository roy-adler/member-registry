import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import smtplib
from flask import Flask

from app import Member, create_app, db, send_email


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


class AdminAppTest(unittest.TestCase):
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

    def add_member(self, name, email, confirmed=True):
        with self.app.app_context():
            member = Member(name=name, email=email, confirmed=confirmed)
            db.session.add(member)
            db.session.commit()
            return member.id


class AdminTestMailPageTest(AdminAppTest):
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


class AdminBulkDeleteTest(AdminAppTest):
    def test_bulk_delete_requires_login(self):
        response = self.client.post('/admin/bulk-delete')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers['Location'])

    def test_dashboard_shows_checkboxes_and_bulk_delete(self):
        self.add_member('Ann', 'ann@example.com', confirmed=True)
        self.add_member('Bob', 'bob@example.com', confirmed=False)
        self.login()
        body = self.client.get('/admin').get_data(as_text=True)
        self.assertIn('name="member_ids"', body)
        self.assertIn('Delete selected', body)

    def test_bulk_delete_removes_selected_members_only(self):
        keep_id = self.add_member('Keep', 'keep@example.com', confirmed=True)
        delete_id = self.add_member('Gone', 'gone@example.com', confirmed=True)
        pending_id = self.add_member('Pending', 'pending@example.com', confirmed=False)
        self.login()
        response = self.client.post('/admin/bulk-delete', data={
            'member_ids': [str(delete_id)],
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('Deleted 1', body)
        with self.app.app_context():
            self.assertIsNone(db.session.get(Member, delete_id))
            self.assertIsNotNone(db.session.get(Member, keep_id))
            self.assertIsNotNone(db.session.get(Member, pending_id))

    def test_bulk_delete_removes_selected_pending(self):
        pending_id = self.add_member('Pending', 'pending@example.com', confirmed=False)
        other_id = self.add_member('Other', 'other@example.com', confirmed=False)
        self.login()
        self.client.post('/admin/bulk-delete', data={
            'member_ids': [str(pending_id)],
        }, follow_redirects=True)
        with self.app.app_context():
            self.assertIsNone(db.session.get(Member, pending_id))
            self.assertIsNotNone(db.session.get(Member, other_id))

    def test_bulk_delete_with_no_selection_deletes_nothing(self):
        member_id = self.add_member('Ann', 'ann@example.com', confirmed=True)
        self.login()
        response = self.client.post('/admin/bulk-delete', data={}, follow_redirects=True)
        body = response.get_data(as_text=True)
        self.assertIn('No members selected', body)
        with self.app.app_context():
            self.assertIsNotNone(db.session.get(Member, member_id))


class RegisterEmailTest(AdminAppTest):
    def register(self, name, email, address='', phone=''):
        with patch('app.send_email', return_value=(True, None)):
            return self.client.post('/register', data={
                'name': name,
                'email': email,
                'address': address,
                'phone': phone,
            }, follow_redirects=True)

    def test_register_trims_and_lowercases_email(self):
        self.register('Ann', '  User@Example.COM  ')
        with self.app.app_context():
            member = Member.query.one()
            self.assertEqual(member.email, 'user@example.com')

    def test_register_rejects_confirmed_email_with_different_case(self):
        self.add_member('Ann', 'user@example.com', confirmed=True)
        response = self.register('Ann', 'USER@example.com')
        self.assertIn('already registered', response.get_data(as_text=True))
        with self.app.app_context():
            self.assertEqual(Member.query.count(), 1)

    def test_register_updates_pending_email_with_different_case(self):
        self.add_member('Ann', 'user@example.com', confirmed=False)
        self.register('Bob', '  USER@example.com  ', address='New St')
        with self.app.app_context():
            members = Member.query.all()
            self.assertEqual(len(members), 1)
            self.assertEqual(members[0].name, 'Bob')
            self.assertEqual(members[0].email, 'user@example.com')
            self.assertEqual(members[0].address, 'New St')

    def test_admin_edit_rejects_duplicate_email_different_case(self):
        keep_id = self.add_member('Ann', 'ann@example.com', confirmed=True)
        other_id = self.add_member('Bob', 'bob@example.com', confirmed=True)
        self.login()
        response = self.client.post(f'/admin/edit/{other_id}', data={
            'name': 'Bob',
            'email': 'ANN@example.com',
            'address': '',
            'phone': '',
        }, follow_redirects=True)
        self.assertIn('already exists', response.get_data(as_text=True))
        with self.app.app_context():
            self.assertEqual(db.session.get(Member, other_id).email, 'bob@example.com')
            self.assertEqual(db.session.get(Member, keep_id).email, 'ann@example.com')

    def test_delete_request_finds_email_ignoring_case_and_space(self):
        self.add_member('Ann', 'user@example.com', confirmed=True)
        with patch('app.send_email', return_value=(True, None)):
            response = self.client.post('/delete-request', data={
                'email': '  USER@example.com  ',
            }, follow_redirects=True)
        self.assertNotIn('No registration found', response.get_data(as_text=True))
        self.assertIn('user@example.com', response.get_data(as_text=True).lower())


if __name__ == '__main__':
    unittest.main()

