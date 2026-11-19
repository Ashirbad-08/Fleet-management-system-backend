const isValidName = (name) => typeof name === 'string' && name.trim().length >= 6 && name.trim().length <= 20;
const isValidEmail = (email) =>
    typeof email === 'string' &&
    /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/i.test(email.trim());
const isValidPassword = (password) => typeof password === 'string'
  && password.length >= 6
  && /[A-Z]/.test(password)
  && /[a-z]/.test(password)
  && /\d/.test(password)
  && /[^A-Za-z0-9]/.test(password);
const isValidPhone = (phone) => typeof phone === 'string'
  && (phone.trim() === '' || (/^\+?[0-9().\-\s]{7,25}$/.test(phone.trim()) && (phone.match(/\d/g) || []).length >= 7));

export { isValidName, isValidEmail, isValidPassword, isValidPhone };
