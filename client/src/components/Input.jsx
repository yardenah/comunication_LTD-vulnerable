export default function Input({ label, type, name, value, onChange }) {
  return (
    <>
      <label>{label}</label>
      <input
        type={type}
        name={name}         
        value={value}
        onChange={onChange}
        required
      />
    </>
  );
}
