using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Duende.IdentityModel.OidcClient;

namespace DesktopClient
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private OidcClient _oidcClient;

        public MainWindow()
        {
            InitializeComponent();
            InitializeOidcClient();
        }

        private void InitializeOidcClient()
        {
            var options = new OidcClientOptions
            {
                Authority = "http://localhost:5147/", // URL de ton serveur d'autorisation
                ClientId = "desktop-client-v2",
                RedirectUri = "http://127.0.0.1:7890/", // URI de redirection locale
                Scope = "openid profile email offline_access api",
                Browser = new SystemBrowser(7890), // Port local
                Policy = new Policy
                {
                    RequireIdentityTokenSignature = false // Désactive la validation de signature pour tests (optionnel)
                }
            };

            _oidcClient = new OidcClient(options);
        }

        private async void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            var result = await _oidcClient.LoginAsync(new LoginRequest());

            if (result.IsError)
            {
                MessageBox.Show($"Erreur de login : {result.Error}");
                return;
            }

            //EmailTextBlock.Text = $"Email : {result.User.Identity.Name}";
            EmailTextBlock.Text = $"Connecté !\n\nAccess Token:\n{result.AccessToken}\n\nEmail:\n{result.User.FindFirst("email")?.Value}";
        }
    }
}