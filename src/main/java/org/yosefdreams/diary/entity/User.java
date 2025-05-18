package org.yosefdreams.diary.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.LocalDateTime;
import java.util.Set;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.yosefdreams.diary.utils.Hash;

@Data
@Entity
@Table(
    name = "users",
    uniqueConstraints = {
      @UniqueConstraint(columnNames = {"username"}),
      @UniqueConstraint(columnNames = {"email"})
    })
public class User {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private long id;

  private String name;
  private String username;
  private String email;
  private String password;
  private String resetToken;

  @Column(columnDefinition = "TIMESTAMP")
  private LocalDateTime resetTokenCreationDate;

  /**
   * Token is sent to the user as a plain text random UUID, but stored hashed. That is, once it was
   * sent to the user, it is no longer existing in its original form, only one way hashed, so that
   * the system itself is unaware of the original value and therefore cannot leak it accidentally.
   *
   * @param token - un-hashed (plain text) token
   */
  public void setPlainTextResetToken(String plainTextToken) {
    var hashedToken = Hash.hashString(plainTextToken);
    this.resetToken = hashedToken;
  }

  /**
   * Password is set by the user and stored hashed. Once set by the user it is no longer existing in
   * its original form,only one way hashed, so that the system itself is unaware of the original
   * value and therefore cannot leak it accidentally.
   *
   * @param plainTextPassword - un-hashed (plain text) password
   */
  public void setַַPlainTextPassword(String plainTextPassword) {
    var hashedPassword = Hash.hashString(plainTextPassword);
    this.password = hashedPassword;
  }

  @Getter
  @Setter
  @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
  @JoinTable(
      name = "user_roles",
      joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
      inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"))
  private Set<Role> roles;
}
