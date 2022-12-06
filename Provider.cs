using MeuProjeto.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Web.Configuration;
using System.Web.Security;
using WebMatrix.WebData;

namespace MeuProjeto.Infrastructure
{
    public class CustomMembershipProvider : ExtendedMembershipProvider
    {
        #region Class Variables

        private int newPasswordLength = 8;
        private string connectionString;
        private string applicationName;
        private bool enablePasswordReset;
        private bool enablePasswordRetrieval;
        private bool requiresQuestionAndAnswer;
        private bool requiresUniqueEmail;
        private int maxInvalidPasswordAttempts;
        private int passwordAttemptWindow;
        private MembershipPasswordFormat passwordFormat;
        private int minRequiredNonAlphanumericCharacters;
        private int minRequiredPasswordLength;
        private string passwordStrengthRegularExpression;
        private MachineKeySection machineKey; //Used when determining encryption key values.

        #endregion

        static public byte[] RandomSalt
        {
            get
            {
                byte[] salt = new byte[48];
                using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
                    rngCsp.GetBytes(salt);
                return salt;
            }
        }

        private byte[] GeneratePasswordHash(byte[] salt, string password)
        {
            Byte[] bytes;
            using (SHA256 hasher = SHA256.Create())
            {
                System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
                bytes = encoding.GetBytes(password);

                hasher.TransformBlock(salt, 0, salt.Length, salt, 0);
                hasher.TransformFinalBlock(bytes, 0, bytes.Length);

                bytes = hasher.Hash;
            }

            return bytes;
        }

        private String GeneratePassword(string newpassword)
        {
            byte[] salt = RandomSalt;
            byte[] passHash = GeneratePasswordHash(salt, newpassword);

            // concatenates the salt and hash in one vector
            byte[] finalData = new byte[salt.Length + passHash.Length];
            Array.Copy(salt, finalData, salt.Length);
            Array.Copy(passHash, 0, finalData, salt.Length, passHash.Length);

            return System.Convert.ToBase64String(finalData);
        }

        private bool ByteArraysEqual(byte[] b1, byte[] b2)
        {
            if (b1 == b2) return true;
            if (b1 == null || b2 == null) return false;
            if (b1.Length != b2.Length) return false;
            for (int i = 0; i < b1.Length; i++)
            {
                if (b1[i] != b2[i]) return false;
            }
            return true;
        } 

        public override bool ConfirmAccount(string accountConfirmationToken)
        {
            throw new NotImplementedException();
        }

        public override bool ConfirmAccount(string userName, string accountConfirmationToken)
        {
            throw new NotImplementedException();
        }

        public override string CreateAccount(string userName, string password, bool requireConfirmationToken)
        {
            throw new NotImplementedException();
        }

        public override string CreateUserAndAccount(string userName, string password, bool requireConfirmation, IDictionary<string, object> values)
        {
            ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(userName, password, true);

            OnValidatingPassword(args);

            if (args.Cancel)
            {
                // return MembershipCreateStatus.InvalidPassword;
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidPassword);
            }

            var CustomMembershipUser = GetUser(userName);

            if (CustomMembershipUser == null)
            {
                // try
                // {
                using (var context = new MeuProjetoContext())
                {
                    var hashedPassword = GeneratePassword(password);

                    var user = new Usuario { 
                        UsuarioId = Guid.NewGuid(),
                        Email = userName,
                        Nome = values["Name"].ToString(),
                        Senha = hashedPassword,
                        Ativo = true
                    };

                    context.Usuarios.Add(user);
                    context.SaveChanges();

                    var membership = new MeuProjeto.Core.Models.Membership();

                    membership.MembershipId = Guid.NewGuid();
                    membership.Usuario = user;
                    membership.Password = hashedPassword;
                    context.Memberships.Add(membership);
                    context.SaveChanges();

                    return MembershipCreateStatus.Success.ToString();
                }
            }
            else
            {
                // return MembershipCreateStatus.DuplicateUserName;
                throw new MembershipCreateUserException(MembershipCreateStatus.DuplicateUserName);
            }
        }

        public override MembershipUser GetUser(string username, bool userIsOnline = true)
        {
            CustomMembershipUser CustomMembershipUser = null;
            using (var context = new MeuProjetoContext())
            {
                try
                {
                    var user = context.Usuarios.Where(u => u.Email == username).SingleOrDefault();

                    if (user != null)
                    {
                        CustomMembershipUser = new CustomMembershipUser(
                            this.Name,
                            user.Email,
                            user.UsuarioId,
                            user.Email,
                            "",
                            "",
                            true,
                            false,
                            user.CreatedOn,
                            DateTime.Now,
                            DateTime.Now,
                            default(DateTime),
                            default(DateTime),
                            user.Email);
                    }
                }
                catch { }
            }

            return CustomMembershipUser;
        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            throw new NotImplementedException();
        }

        public override string GetUserNameByEmail(string email)
        {
            throw new NotImplementedException();
        }

        public override int MaxInvalidPasswordAttempts
        {
            get { throw new NotImplementedException(); }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { throw new NotImplementedException(); }
        }

        public override int MinRequiredPasswordLength
        {
            get { throw new NotImplementedException(); }
        }

        public override int PasswordAttemptWindow
        {
            get { throw new NotImplementedException(); }
        }

        public override System.Web.Security.MembershipPasswordFormat PasswordFormat
        {
            get { throw new NotImplementedException(); }
        }

        public override string PasswordStrengthRegularExpression
        {
            get { throw new NotImplementedException(); }
        }

        public override bool RequiresQuestionAndAnswer
        {
            get { throw new NotImplementedException(); }
        }

        public override bool RequiresUniqueEmail
        {
            get { throw new NotImplementedException(); }
        }

        public override string ResetPassword(string username, string answer)
        {
            throw new NotImplementedException();
        }

        public override bool UnlockUser(string userName)
        {
            throw new NotImplementedException();
        }

        public override void UpdateUser(System.Web.Security.MembershipUser user)
        {
            throw new NotImplementedException();
        }

        public override bool ValidateUser(string username, string password)
        {
            using (var context = new MeuProjetoContext())
            {
                if (context == null) throw new InvalidOperationException();

                var user = (from u in context.Usuarios
                            where u.Email == username && u.Ativo == true
                            select u).FirstOrDefault();

                if (user != null)
                {
                    byte[] pwdHash = GeneratePasswordHash(user.Salt, password);
                    if (ByteArraysEqual(pwdHash, user.Hash))
                    {
                        bool isAdm = true;

                        System.Web.Security.FormsAuthenticationTicket ticket = new System.Web.Security.FormsAuthenticationTicket(1,
                          user.UsuarioId.ToString() + "#" + username,
                          DateTime.Now,
                          DateTime.Now.AddMinutes(15),
                          false,
                          isAdm ? "#" + user.Nome : user.Nome,
                          System.Web.Security.FormsAuthentication.FormsCookiePath);

                        #if DEBUG
                        System.Diagnostics.Debugger.Log(0, "SEC", "User " + username + " logged in at " + ticket.IssueDate.ToString());
                        #endif

                        // Encrypt the ticket.
                        string encTicket = System.Web.Security.FormsAuthentication.Encrypt(ticket);

                        HttpContext.Current.Response.Cookies.Add(new HttpCookie(System.Web.Security.FormsAuthentication.FormsCookieName, encTicket));
                        return true;
                    }
                }

                return false;
            }
        }
    }
}
