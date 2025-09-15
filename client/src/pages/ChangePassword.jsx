import { useState } from 'react';
import Input from '../components/Input';
import Button from '../components/Button';
import { changePassword } from '../api';
import { useNavigate } from 'react-router-dom';

export default function ChangePassword() {
  const [formData, setFormData] = useState({
    username:'',
    oldPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    if (formData.newPassword !== formData.confirmPassword) {
      alert('New password and confirm password do not match.');
      setLoading(false);
      return;
    }

    try {
      await changePassword(formData.username,formData.oldPassword, formData.newPassword);

      alert('Password changed successfully');
      setFormData({
        email:'',
        oldPassword: '',
        newPassword: '',
        confirmPassword: '',
      });

      navigate('/login');
    } catch (err) {
      alert(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h1>Change Password</h1>
      <form onSubmit={handleSubmit}>
        <Input
          label="Username"
          type="text"
          name="username"
          value={formData.username}
          onChange={handleChange}
          required
        />
        <Input
          label="Old Password"
          type="password"
          name="oldPassword"
          value={formData.oldPassword}
          onChange={handleChange}
          required
        />
        <Input
          label="New Password"
          type="password"
          name="newPassword"
          value={formData.newPassword}
          onChange={handleChange}
          required
        />
        <div className="password-requirements">
          Password must be at least 10 characters long and include uppercase letters, lowercase letters, numbers, and special characters.
        </div>
        <Input
          label="Confirm Password"
          type="password"
          name="confirmPassword"
          value={formData.confirmPassword}
          onChange={handleChange}
          required
        />

        {loading ? (
          <button className="spinner-button" disabled>
            <div className="spinner"></div>
          </button>
        ) : (
          <Button text="Change Password" />
        )}
      </form>
    </div>
  );
}
