import { Resend } from "resend";

export const resend = new Resend(process.env.RESEND_API_KEY);

export const sendOtpEmail = async (
  email: string,
  sub: string,
  content: string,
) => {
  await resend.emails.send({
    // from:process.env.MAIL_FROM!,
    from: "Acme <onboarding@resend.dev>",
    to: email,
    subject: sub,
    html: content,
  });
};
