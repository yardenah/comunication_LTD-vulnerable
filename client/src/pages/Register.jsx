import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { registerUser, getPasswordConfig } from "../api"; 
import Input from "../components/Input";
import Button from "../components/Button";

export default function Register() {
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
    confirmPassword: "",
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
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (formData.password !== formData.confirmPassword) {
      alert("Passwords do not match");
      return;
    }

    setLoading(true);
    try {
      await registerUser({
        username: formData.username,
        email: formData.email,
        password: formData.password,
      });

      alert("Registration successful! Redirecting to login...");

      setFormData({
        username: "",
        email: "",
        password: "",
        confirmPassword: "",
      });

      setTimeout(() => {
        navigate("/login");
      }, 2000);
    } catch (err) {
      alert(err.message || "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h1>Register</h1>

      <form onSubmit={handleSubmit}>
        <Input
          label="Username"
          type="text"
          name="username"
          value={formData.username}
          onChange={handleChange}
        />
        <Input
          label="Email"
          type="email"
          name="email"
          value={formData.email}
          onChange={handleChange}
        />
        <Input
          label="Password"
          type="password"
          name="password"
          value={formData.password}
          onChange={handleChange}
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
          label="Confirm Password"
          type="password"
          name="confirmPassword"
          value={formData.confirmPassword}
          onChange={handleChange}
        />

        {loading ? (
          <button className="spinner-button" disabled>
            <div className="spinner"></div>
          </button>
        ) : (
          <Button text="Register" />
        )}
      </form>

      <div className="login-link">
        Already have an account? <a href="/">Click here</a>
      </div>
    </div>
  );
}
