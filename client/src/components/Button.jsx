export default function Button({ text, onClick, loading = false, type = "submit" }) {
  return (
    <button
      type={type}
      onClick={onClick}
      className={`custom-button ${loading ? 'loading' : ''}`}
      disabled={loading}
    >
      {loading ? <div className="spinner"></div> : text}
    </button>
  );
}
