using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Text.Json;
using System.Globalization;

namespace BibliothequeSystem
{
    // Interface pour la gestion des emprunts
    public interface IEmpruntable
    {
        bool EstDisponible { get; }
        DateTime? DateEmprunt { get; set; }
        string EmprunteurId { get; set; }
        void Emprunter(string utilisateurId);
        void Retourner();
    }

    // Classe abstraite pour les documents
    public abstract class Document : IEmpruntable
    {
        public string Id { get; set; }
        public string Titre { get; set; }
        public string Auteur { get; set; }
        public DateTime DatePublication { get; set; }
        public bool EstDisponible { get; private set; } = true;
        public DateTime? DateEmprunt { get; set; }
        public string EmprunteurId { get; set; }

        protected Document(string id, string titre, string auteur, DateTime datePublication)
        {
            Id = id;
            Titre = titre;
            Auteur = auteur;
            DatePublication = datePublication;
        }

        public virtual void Emprunter(string utilisateurId)
        {
            if (!EstDisponible)
                throw new InvalidOperationException("Document déjà emprunté");
            
            EstDisponible = false;
            DateEmprunt = DateTime.Now;
            EmprunteurId = utilisateurId;
        }

        public virtual void Retourner()
        {
            EstDisponible = true;
            DateEmprunt = null;
            EmprunteurId = null;
        }

        public abstract string GetTypeDocument();
        public abstract double CalculerPenalite();
    }

    // Classes dérivées pour différents types de documents
    public class Livre : Document
    {
        public int NombrePages { get; set; }
        public string ISBN { get; set; }
        public string Genre { get; set; }

        public Livre(string id, string titre, string auteur, DateTime datePublication, 
                    int nombrePages, string isbn, string genre) 
            : base(id, titre, auteur, datePublication)
        {
            NombrePages = nombrePages;
            ISBN = isbn;
            Genre = genre;
        }

        public override string GetTypeDocument() => "Livre";

        public override double CalculerPenalite()
        {
            if (DateEmprunt == null) return 0;
            var joursRetard = (DateTime.Now - DateEmprunt.Value).Days - 14; // 14 jours max
            return joursRetard > 0 ? joursRetard * 0.5 : 0; // 0.5€ par jour de retard
        }
    }

    public class Revue : Document
    {
        public int NumeroEdition { get; set; }
        public string Periodicite { get; set; }

        public Revue(string id, string titre, string auteur, DateTime datePublication,
                    int numeroEdition, string periodicite)
            : base(id, titre, auteur, datePublication)
        {
            NumeroEdition = numeroEdition;
            Periodicite = periodicite;
        }

        public override string GetTypeDocument() => "Revue";

        public override double CalculerPenalite()
        {
            if (DateEmprunt == null) return 0;
            var joursRetard = (DateTime.Now - DateEmprunt.Value).Days - 7; // 7 jours max pour revue
            return joursRetard > 0 ? joursRetard * 0.3 : 0; // 0.3€ par jour de retard
        }
    }

    public class DVD : Document
    {
        public int DureeMinutes { get; set; }
        public string Realisateur { get; set; }
        public string Genre { get; set; }

        public DVD(string id, string titre, string realisateur, DateTime datePublication,
                  int dureeMinutes, string genre)
            : base(id, titre, realisateur, datePublication)
        {
            DureeMinutes = dureeMinutes;
            Realisateur = realisateur;
            Genre = genre;
        }

        public override string GetTypeDocument() => "DVD";

        public override double CalculerPenalite()
        {
            if (DateEmprunt == null) return 0;
            var joursRetard = (DateTime.Now - DateEmprunt.Value).Days - 3; // 3 jours max pour DVD
            return joursRetard > 0 ? joursRetard * 1.0 : 0; // 1€ par jour de retard
        }
    }

    // Classe pour gérer les utilisateurs
    public class Utilisateur
    {
        public string Id { get; set; }
        public string Nom { get; set; }
        public string Prenom { get; set; }
        public string Email { get; set; }
        public DateTime DateInscription { get; set; }
        public List<string> DocumentsEmpruntes { get; set; } = new List<string>();
        public double PenalitesTotales { get; set; }

        public Utilisateur(string id, string nom, string prenom, string email)
        {
            Id = id;
            Nom = nom;
            Prenom = prenom;
            Email = email;
            DateInscription = DateTime.Now;
        }

        public bool PeutEmprunter()
        {
            return DocumentsEmpruntes.Count < 5 && PenalitesTotales < 10.0;
        }
    }

    // Gestionnaire de sécurité avec mot de passe caché
    public static class SecurityManager
    {

        public static string GetHiddenPassword()
        {
            return Encoding.UTF8.GetString(_hiddenKey);
        }

        public static bool VerifyAdminAccess(string password)
        {
            string hiddenPassword = GetHiddenPassword();
            return password == hiddenPassword || ComputeHash(password) == _adminHash;
        }

        private static string ComputeHash(string input)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(input));
                return Convert.ToHexString(bytes).ToLower();
            }
        }

        public static string EncryptData(string data, string key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
                aes.IV = new byte[16];

                using (var encryptor = aes.CreateEncryptor())
                using (var ms = new MemoryStream())
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                using (var writer = new StreamWriter(cs))
                {
                    writer.Write(data);
                    writer.Close();
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }
    }

    // Gestionnaire principal de la bibliothèque
    public class BibliothequeManager
    {
        private readonly Dictionary<string, Document> _documents;
        private readonly Dictionary<string, Utilisateur> _utilisateurs;
        private readonly List<string> _logActivites;
        private readonly Random _random;

        public BibliothequeManager()
        {
            _documents = new Dictionary<string, Document>();
            _utilisateurs = new Dictionary<string, Utilisateur>();
            _logActivites = new List<string>();
            _random = new Random();
            InitialiserDonneesTest();
        }

        private void InitialiserDonneesTest()
        {
            // Ajouter des livres
            AjouterDocument(new Livre("L001", "Le Petit Prince", "Antoine de Saint-Exupéry", 
                new DateTime(1943, 4, 6), 96, "978-2-07-040839-2", "Fiction"));
            
            AjouterDocument(new Livre("L002", "1984", "George Orwell", 
                new DateTime(1949, 6, 8), 328, "978-0-452-28423-4", "Science-Fiction"));

            AjouterDocument(new Livre("L003", "L'Étranger", "Albert Camus", 
                new DateTime(1942, 1, 1), 159, "978-2-07-036002-1", "Philosophie"));

            // Ajouter des revues
            AjouterDocument(new Revue("R001", "National Geographic", "Divers", 
                DateTime.Now.AddMonths(-1), 245, "Mensuelle"));

            AjouterDocument(new Revue("R002", "Science et Vie", "Divers", 
                DateTime.Now.AddDays(-15), 1287, "Mensuelle"));

            // Ajouter des DVDs
            AjouterDocument(new DVD("D001", "Inception", "Christopher Nolan", 
                new DateTime(2010, 7, 16), 148, "Science-Fiction"));

            AjouterDocument(new DVD("D002", "Le Parrain", "Francis Ford Coppola", 
                new DateTime(1972, 3, 24), 175, "Drame"));

            // Ajouter des utilisateurs
            AjouterUtilisateur(new Utilisateur("U001", "Martin", "Jean", "jean.martin@email.com"));
            AjouterUtilisateur(new Utilisateur("U002", "Dubois", "Marie", "marie.dubois@email.com"));
            AjouterUtilisateur(new Utilisateur("U003", "Lambert", "Pierre", "pierre.lambert@email.com"));
        }

        public void AjouterDocument(Document document)
        {
            _documents[document.Id] = document;
            AjouterLog($"Document ajouté: {document.GetTypeDocument()} - {document.Titre}");
        }

        public void AjouterUtilisateur(Utilisateur utilisateur)
        {
            _utilisateurs[utilisateur.Id] = utilisateur;
            AjouterLog($"Utilisateur ajouté: {utilisateur.Prenom} {utilisateur.Nom}");
        }

        public bool EmprunterDocument(string documentId, string utilisateurId)
        {
            if (!_documents.ContainsKey(documentId) || !_utilisateurs.ContainsKey(utilisateurId))
                return false;

            var document = _documents[documentId];
            var utilisateur = _utilisateurs[utilisateurId];

            if (!document.EstDisponible || !utilisateur.PeutEmprunter())
                return false;

            try
            {
                document.Emprunter(utilisateurId);
                utilisateur.DocumentsEmpruntes.Add(documentId);
                AjouterLog($"Emprunt: {utilisateur.Prenom} {utilisateur.Nom} - {document.Titre}");
                return true;
            }
            catch (Exception ex)
            {
                AjouterLog($"Erreur emprunt: {ex.Message}");
                return false;
            }
        }

        public bool RetournerDocument(string documentId)
        {
            if (!_documents.ContainsKey(documentId))
                return false;

            var document = _documents[documentId];
            if (document.EstDisponible)
                return false;

            var utilisateur = _utilisateurs[document.EmprunteurId];
            var penalite = document.CalculerPenalite();
            
            if (penalite > 0)
            {
                utilisateur.PenalitesTotales += penalite;
                AjouterLog($"Pénalité appliquée: {penalite:C} pour {utilisateur.Prenom} {utilisateur.Nom}");
            }

            document.Retourner();
            utilisateur.DocumentsEmpruntes.Remove(documentId);
            AjouterLog($"Retour: {document.Titre} par {utilisateur.Prenom} {utilisateur.Nom}");
            
            return true;
        }

        public List<Document> RechercherDocuments(string terme)
        {
            return _documents.Values
                .Where(d => d.Titre.Contains(terme, StringComparison.OrdinalIgnoreCase) ||
                           d.Auteur.Contains(terme, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        public Dictionary<string, int> ObtenirStatistiques()
        {
            return new Dictionary<string, int>
            {
                ["TotalDocuments"] = _documents.Count,
                ["DocumentsDisponibles"] = _documents.Values.Count(d => d.EstDisponible),
                ["DocumentsEmpruntes"] = _documents.Values.Count(d => !d.EstDisponible),
                ["TotalUtilisateurs"] = _utilisateurs.Count,
                ["Livres"] = _documents.Values.OfType<Livre>().Count(),
                ["Revues"] = _documents.Values.OfType<Revue>().Count(),
                ["DVDs"] = _documents.Values.OfType<DVD>().Count()
            };
        }

        public void GenererRapportActivites()
        {
            Console.WriteLine("\n=== RAPPORT D'ACTIVITÉS ===");
            Console.WriteLine($"Nombre total d'activités: {_logActivites.Count}");
            Console.WriteLine("\nDernières activités:");
            
            foreach (var activite in _logActivites.TakeLast(10))
            {
                Console.WriteLine($"- {activite}");
            }
        }

        private void AjouterLog(string message)
        {
            _logActivites.Add($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}");
        }

        public void AfficherMenuPrincipal()
        {
            Console.Clear();
            Console.WriteLine("╔══════════════════════════════════════╗");
            Console.WriteLine("║        SYSTÈME DE BIBLIOTHÈQUE       ║");
            Console.WriteLine("╠══════════════════════════════════════╣");
            Console.WriteLine("║ 1. Rechercher des documents          ║");
            Console.WriteLine("║ 2. Emprunter un document             ║");
            Console.WriteLine("║ 3. Retourner un document             ║");
            Console.WriteLine("║ 4. Afficher les statistiques         ║");
            Console.WriteLine("║ 5. Rapport d'activités               ║");
            Console.WriteLine("║ 6. Accès administrateur              ║");
            Console.WriteLine("║ 0. Quitter                           ║");
            Console.WriteLine("╚══════════════════════════════════════╝");
        }

        public void ExecuterApplication()
        {
            bool continuer = true;
            
            while (continuer)
            {
                AfficherMenuPrincipal();
                Console.Write("\nChoisissez une option: ");
                
                if (int.TryParse(Console.ReadLine(), out int choix))
                {
                    switch (choix)
                    {
                        case 1:
                            ExecuterRecherche();
                            break;
                        case 2:
                            ExecuterEmprunt();
                            break;
                        case 3:
                            ExecuterRetour();
                            break;
                        case 4:
                            AfficherStatistiques();
                            break;
                        case 5:
                            GenererRapportActivites();
                            break;
                        case 6:
                            AccesAdministrateur();
                            break;
                        case 0:
                            continuer = false;
                            Console.WriteLine("Au revoir !");
                            break;
                        default:
                            Console.WriteLine("Option invalide !");
                            break;
                    }
                }
                else
                {
                    Console.WriteLine("Veuillez entrer un nombre valide !");
                }
                
                if (continuer)
                {
                    Console.WriteLine("\nAppuyez sur une touche pour continuer...");
                    Console.ReadKey();
                }
            }
        }

        private void ExecuterRecherche()
        {
            Console.Write("\nEntrez votre terme de recherche: ");
            string terme = Console.ReadLine();
            
            var resultats = RechercherDocuments(terme);
            
            if (resultats.Any())
            {
                Console.WriteLine($"\n{resultats.Count} document(s) trouvé(s):");
                foreach (var doc in resultats)
                {
                    string statut = doc.EstDisponible ? "Disponible" : "Emprunté";
                    Console.WriteLine($"- [{doc.Id}] {doc.GetTypeDocument()}: {doc.Titre} par {doc.Auteur} ({statut})");
                }
            }
            else
            {
                Console.WriteLine("Aucun document trouvé.");
            }
        }

        private void ExecuterEmprunt()
        {
            Console.Write("\nID du document à emprunter: ");
            string docId = Console.ReadLine();
            Console.Write("ID de l'utilisateur: ");
            string userId = Console.ReadLine();
            
            if (EmprunterDocument(docId, userId))
            {
                Console.WriteLine("Emprunt effectué avec succès !");
            }
            else
            {
                Console.WriteLine("Impossible d'effectuer l'emprunt.");
            }
        }

        private void ExecuterRetour()
        {
            Console.Write("\nID du document à retourner: ");
            string docId = Console.ReadLine();
            
            if (RetournerDocument(docId))
            {
                Console.WriteLine("Retour effectué avec succès !");
            }
            else
            {
                Console.WriteLine("Impossible d'effectuer le retour.");
            }
        }

        private void AfficherStatistiques()
        {
            var stats = ObtenirStatistiques();
            Console.WriteLine("\n=== STATISTIQUES ===");
            foreach (var stat in stats)
            {
                Console.WriteLine($"{stat.Key}: {stat.Value}");
            }
        }

        private void AccesAdministrateur()
        {
            Console.Write("\nMot de passe administrateur: ");
            string motDePasse = Console.ReadLine();
            
            if (SecurityManager.VerifyAdminAccess(motDePasse))
            {
                Console.WriteLine("\nAccès administrateur accordé !");
                Console.WriteLine($"Mot de passe caché révélé: {SecurityManager.GetHiddenPassword()}");
                Console.WriteLine("\nFonctionnalités administrateur disponibles...");
                // Ici on pourrait ajouter des fonctionnalités d'admin
            }
            else
            {
                Console.WriteLine("Accès refusé !");
            }
        }
    }

    // Classe principale pour lancer l'application
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                Console.OutputEncoding = Encoding.UTF8;
                Console.WriteLine("Initialisation du système de bibliothèque...");
                
                var bibliotheque = new BibliothequeManager();
                bibliotheque.ExecuterApplication();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur critique: {ex.Message}");
                Console.WriteLine("Appuyez sur une touche pour quitter...");
                Console.ReadKey();
            }
        }
    }
}
