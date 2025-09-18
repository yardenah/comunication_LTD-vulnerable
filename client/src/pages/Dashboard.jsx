import { useState, useEffect } from 'react';
import Input from '../components/Input';
import Button from '../components/Button';
import { useNavigate } from 'react-router-dom';
import { getClients, addClient } from '../api';

export default function ClientsPage() {
  const [clientData, setClientData] = useState({
    fullName: '',
    email: '',
    phone: '',
    packageName: '',
    sector: '',
    address: '',
  });

  const navigate = useNavigate();
  const [clients, setClients] = useState([]);
  const [loadingClients, setLoadingClients] = useState(false);
  const [addingClient, setAddingClient] = useState(false);

  useEffect(() => {
    fetchClients();
  }, []);

  const fetchClients = async () => {
    setLoadingClients(true);
    try {
      const data = await getClients();
      setClients(data);
    } catch (err) {
      alert(err.message);
    } finally {
      setLoadingClients(false);
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setClientData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!clientData.fullName.trim()) {
      alert('Please enter full name');
      return;
    }

    if (
      clientData.email &&
      !/^[\w-.]+@([\w-]+\.)+[\w-]{2,4}$/.test(clientData.email)
    ) {
      alert('Please enter a valid email');
      return;
    }

    setAddingClient(true);
    try {
      await addClient(clientData);

      // Vulnerable — stored XSS (showing raw user input in an alert/HTML may execute injected scripts)
      alert(`Client added: ${clientData.fullName}`);

      // Fetch all clients to refresh the list
      await fetchClients();

      setClientData({
        fullName: '',
        email: '',
        phone: '',
        packageName: '',
        sector: '',
        address: '',
      });
    } catch (err) {
      alert(err.message);
    } finally {
      setAddingClient(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('user');
    navigate('/');
  };

  return (
    <div className="container">
      <div className="top-bar">
        <Button
          text="Logout"
          onClick={handleLogout}
          className="logout-button"
        />
        <Button
          text="Change Password"
          onClick={() => navigate('/change-password')}
          className="change-password"
        />
      </div>

      <h1>Clients Management</h1>

      <section className="form-section">
        <form onSubmit={handleSubmit} className="client-form">
          <Input
            label="Full Name"
            name="fullName"
            type="text"
            value={clientData.fullName}
            onChange={handleChange}
            className="form-input"
          />
          <Input
            label="Email"
            name="email"
            type="email"
            value={clientData.email}
            onChange={handleChange}
            className="form-input"
          />
          <Input
            label="Phone"
            name="phone"
            type="text"
            value={clientData.phone}
            onChange={handleChange}
            className="form-input"
          />
          <Input
            label="Package Name"
            name="packageName"
            type="text"
            value={clientData.packageName}
            onChange={handleChange}
          />
          <Input
            label="Sector"
            name="sector"
            type="text"
            value={clientData.sector}
            onChange={handleChange}
          />
          <Input
            label="Address"
            name="address"
            type="text"
            value={clientData.address}
            onChange={handleChange}
            className="form-input"
          />

          {addingClient ? (
            <button className="spinner-button" disabled>
              <div className="spinner"></div>
            </button>
          ) : (
            <Button text="Add Client" className="submit-button" />
          )}
        </form>
      </section>

      <section className="clients-list-section">
        <h2>Client List</h2>
        {loadingClients && clients.length === 0 ? (
          <p>Loading clients...</p>
        ) : clients.length === 0 ? (
          <p>No clients found.</p>
        ) : (
          <table className="client-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Phone</th>
                <th>Package</th>
                <th>Sector</th>
                <th>Address</th>
              </tr>
            </thead>
            <tbody>
              {clients.map((client) => (
                <tr key={client.id}>
                  <td>
                    <div
                      dangerouslySetInnerHTML={{ __html: client.fullName }}
                    />
                  </td>
                  <td>
                    <div dangerouslySetInnerHTML={{ __html: client.email }} />
                  </td>
                  <td>
                    <div dangerouslySetInnerHTML={{ __html: client.phone }} />
                  </td>
                  <td>
                    <div
                      dangerouslySetInnerHTML={{ __html: client.packageName }}
                    />
                  </td>
                  <td>
                    <div dangerouslySetInnerHTML={{ __html: client.sector }} />
                  </td>
                  <td>
                    <div dangerouslySetInnerHTML={{ __html: client.address }} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
