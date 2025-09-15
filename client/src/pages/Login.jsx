import { useState } from 'react';
import Input from '../components/Input';
import Button from '../components/Button';
import { Link, useNavigate } from 'react-router-dom';
import { loginUser } from '../api';

export default function Login() {
  const [formData, setFormData] = useState({
    username: '',
    password: '',
  });
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const data = await loginUser(formData.username, formData.password);

      localStorage.setItem("user", JSON.stringify(data));

      alert("Login successful");
      navigate("/dashboard");
    } catch (err) {
      alert(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h1>Login</h1>
      <form onSubmit={handleLogin}>
        <Input
          label="Username"
          type="text"
          name="username"
          value={formData.username}
          onChange={handleChange}
        />
        <Input
          label="Password"
          type="password"
          name="password"
          value={formData.password}
          onChange={handleChange}
        />

        {loading ? (
          <button className="spinner-button" disabled>
            <div className="spinner"></div>
          </button>
        ) : (
          <Button text="Login" />
        )}
      </form>

      <p>
        <Link to="/forgot-password">Forgot Password?</Link>
      </p>
      <p>
        <Link to="/register">Create Account</Link>
      </p>
    </div>
  );
}
