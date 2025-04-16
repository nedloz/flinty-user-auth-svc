const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);

const send2FACode = async (email, code) => {
  try {
    const response = await resend.emails.send({
      from: 'onboarding@resend.dev',
      to: email,
    //   to: "andrukuzminkuzmin@yandex.ru",
      subject: 'Ваш код подтверждения',
      html: `<p>Код подтверждения: <strong>${code}</strong></p>`,
    });
    console.log("код отправлен");
    return response;
  } catch (err) {
    throw err;
  }
};

module.exports = send2FACode