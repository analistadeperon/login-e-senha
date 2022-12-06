namespace MeuProjeto.Controllers
{
    public class LoginController : Controller
    {
        private MeuProjetoContext _db = new MeuProjetoContext();
        //
        // GET: /Login/

        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Index(UserLogin userLogin)
        {
            if (ModelState.IsValid && WebSecurity.Login(userLogin.Username, userLogin.Password, persistCookie: true))
            {
                return RedirectToAction("Index", "Home", new { area = "" });
            }

            // Se chegou aqui, re-exibir form. Modelo inválido.
            ModelState.AddModelError("", "Usuário ou senha incorretos.");
            return View(userLogin);
        }

        public ActionResult RecuperarSenha()
        {
            ViewBag.ErrorMessage = "";
            return View();
        }

        [HttpPost]
        public ActionResult RecuperarSenha(string email)
        {
            string errorMsg = string.Empty;

            if (!string.IsNullOrEmpty(email))
            {
                List<Usuario> users = _db.Usuarios.Where(usr => usr.Email == email).ToList();

                if (users.Count == 0)
                {
                    errorMsg = "E-Mail não encontrado";
                }
                else
                {
                    Usuario user = users[0];

                    string url = string.Format("{0}/{1}/{2}", Request.Url.GetLeftPart(UriPartial.Authority), "Login/ResetPassword", user.UsuarioId);

                    string bodyMail = "Olá " + user.Nome + @"\r\n";
                    bodyMail += "Para redefinir a sua senha clique <a href=\"" + url + "\">aqui</a><br>";

                    EmailMessage msg = new EmailMessage();
                    msg.To = user.Email;
                    msg.Subject = "Redefinir senha";
                    msg.Body = bodyMail;
                    msg.Send();
                    errorMsg = "E-Mail enviado com sucesso";
                }
            }
            else
            {
                errorMsg = "E-Mail não pode estar em branco";
            }

            ViewBag.ErrorMessage = errorMsg;
            return View();
        }

        public ActionResult Logout()
        {
            WebSecurity.Logout();
            return RedirectToAction("Index", "Login", new { area = "" });
        }

        protected override void Dispose(bool disposing)
        {
            _db.Dispose();
            base.Dispose(disposing);
        }
    }
}
