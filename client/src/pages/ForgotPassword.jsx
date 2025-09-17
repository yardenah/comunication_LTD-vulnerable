import { useState, useEffect } from 'react';
import { useNavigate } from "react-router-dom";
import { requestPasswordReset, resetPassword, getPasswordConfig } from '../api';
import Input from '../components/Input';
import Button from '../components/Button';

export default function ForgotPassword() {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState({
    username: '',
    token: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [loading, setLoading] = useState(false);
  const [passwordConfig, setPasswordConfig] = useState(null);
  const navigate = useNavigate();

    // Fetch password configuration on component mount
    useEffect(() => {
      const fetchPasswordConfig = async () => {
        try {
          const config = await getPasswordConfig();
          setPasswordConfig(config);
        } catch (error) {
          console.error('Failed to fetch password configuration:', error);
          // Set default values if fetch fails
          setPasswordConfig({
            passwordLength: 10,
            passwordLimitation: {
              includeUppercase: true,
              includeLowercase: true,
              includeNumbers: true,
              includeSpecial: true,
            }
          });
        }
      };
  
      fetchPasswordConfig();
    }, []);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleRequestReset = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      await requestPasswordReset(formData.username);
      alert(
        "If an account with that username exists, a reset token has been sent to your email address."
      );
      setFormData((prev) => ({ ...prev, username: '' })); 
      setStep(2);
    } catch (err) {
      alert(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();

    if (formData.newPassword !== formData.confirmPassword) {
      alert('Passwords do not match');
      return;
    }

    setLoading(true);

    try {
      await resetPassword({
        username: formData.username,
        token: formData.token,
        newPassword: formData.newPassword,
      });
      alert('Password reset successful! You can now login with your new password.');
      setFormData({
        username: '',
        token: '',
        newPassword: '',
        confirmPassword: '',
      });
      setStep(1);
      navigate("/login");
    } catch (err) {
      alert(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h2>Forgot Password</h2>

      {step === 1 ? (
        <form onSubmit={handleRequestReset}>
          <Input
            label="Username"
            type="text"
            name="username"
            value={formData.username}
            onChange={handleChange}
            required
          />

          {loading ? (
            <button className="spinner-button" disabled>
              <div className="spinner"></div>
            </button>
          ) : (
            <Button text="Request Reset Token" />
          )}
        </form>
      ) : (
        <form onSubmit={handleResetPassword}>
          <Input
            label="Username"
            type="text"
            name="username"
            value={formData.username}
            onChange={handleChange}
            required
          />  

          <Input
            label="Reset Token"
            type="password"
            name="token"
            value={formData.token}
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
          
          <small className="password-requirements">
          {passwordConfig ? (
            <>
              Password must be at least {passwordConfig.passwordLength} characters long
              {passwordConfig.passwordLimitation.includeUppercase && ', include uppercase letters'}
              {passwordConfig.passwordLimitation.includeLowercase && ', include lowercase letters'}
              {passwordConfig.passwordLimitation.includeNumbers && ', include numbers'}
              {passwordConfig.passwordLimitation.includeSpecial && ', include special characters'}
              .
            </>
          ) : (
            'Loading password requirements...'
          )}
        </small>

          <Input
            label="Confirm New Password"
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
            <Button text="Reset Password" />
          )}
        </form>
      )}

      <div className="login-link">
        Ready to login? <a href="/">Click here</a>
      </div>
    </div>
  );
}
