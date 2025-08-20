package org.yosefdreams.diary.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

/** Service for sending emails. */
@Service
public class EmailService {

  private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

  private final JavaMailSender mailSender;
  private final String fromEmail;
  private final String resetPasswordSubject;
  private final String frontendResetPasswordUrl;

  public EmailService(
      JavaMailSender mailSender,
      @Value("${app.email.from}") String fromEmail,
      @Value("${app.email.reset-password.subject}") String resetPasswordSubject,
      @Value("${app.frontend.reset-password-url}") String frontendResetPasswordUrl) {
    this.mailSender = mailSender;
    this.fromEmail = fromEmail;
    this.resetPasswordSubject = resetPasswordSubject;
    this.frontendResetPasswordUrl = frontendResetPasswordUrl;
  }

  /**
   * Sends a password reset email to the specified recipient.
   *
   * @param toEmail the email address of the recipient
   * @param resetToken the reset token to include in the email
   */
  public void sendPasswordResetEmail(String toEmail, String resetToken) {
    try {
      String resetUrl = String.format("%s?token=%s", frontendResetPasswordUrl, resetToken);

      String message =
          String.format(
              "To reset your password, click the link below:\n\n%s\n\n"
                  + "This link will expire in 15 minutes.\n"
                  + "If you didn't request a password reset, please ignore this email.",
              resetUrl);

      SimpleMailMessage mailMessage = new SimpleMailMessage();
      mailMessage.setFrom(fromEmail);
      mailMessage.setTo(toEmail);
      mailMessage.setSubject(resetPasswordSubject);
      mailMessage.setText(message);

      mailSender.send(mailMessage);
      logger.info("Password reset email sent to: {}", toEmail);
    } catch (Exception e) {
      logger.error("Error sending password reset email to: " + toEmail, e);
      throw new RuntimeException("Error sending password reset email", e);
    }
  }
}
