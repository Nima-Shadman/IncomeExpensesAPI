from .test_setup import TestSetUp
from ..models import User

class TetViews(TestSetUp):
    def test_user_cannot_register_with_no_data(self):
        resp = self.client.post(self.register_url)
        self.assertEqual(resp.status_code, 400)
    
    def test_user_can_register_correctly(self):
        resp = self.client.post(self.register_url,self.user_data,format="json")
        self.assertEqual(resp.status_code, 201)

    def test_user_cannot_login_with_unverified_email(self):
        self.client.post(self.register_url,self.user_data,format="json")
        resp = self.client.post(self.login_url,self.user_data,format="json")
        self.assertEqual(resp.status_code,401)

    def test_user_can_login_after_verification(self):
        response = self.client.post(self.register_url,self.user_data,format="json")
        email = response.data['email']
        user = User.objects.get(email=email)
        user.is_verified = True
        user.save()
        resp = self.client.post(self.login_url,self.user_data,format="json")
        self.assertEqual(resp.status_code,200)