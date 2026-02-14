import Brevo from "@getbrevo/brevo";

const apiInstance = new Brevo.TransactionalEmailsApi();

apiInstance.setApiKey(
  Brevo.TransactionalEmailsApiApiKeys.apiKey,
  process.env.BREVO_API_KEY
);

export const sendSecurityAlert = async ({
  to,
  ip,
  userAgent,
  time
}) => {
  try {
    const sendSmtpEmail = new Brevo.SendSmtpEmail();

    sendSmtpEmail.subject = "Suspicious Login Detected";
    sendSmtpEmail.htmlContent = `
      <h3>New Login Detected</h3>
      <p><strong>Time:</strong> ${time}</p>
      <p><strong>IP Address:</strong> ${ip}</p>
      <p><strong>Device:</strong> ${userAgent}</p>
      <p>If this was not you, please change your password immediately.</p>
    `;

    sendSmtpEmail.sender = {
      name: process.env.EMAIL_FROM_NAME,
      email: process.env.EMAIL_FROM
    };

    sendSmtpEmail.to = [{ email: to }];

    await apiInstance.sendTransacEmail(sendSmtpEmail);

  } catch (error) {
    console.error("Brevo email error:", error?.response?.body || error);
  }
};
