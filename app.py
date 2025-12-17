from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

# ❌ VULNÉRABILITÉ 1: Secrets en dur dans le code
DATABASE_PASSWORD = "admin123"
SECRET_KEY = "my-secret-key-12345"
app.config['SECRET_KEY'] = SECRET_KEY

def init_db():
    """Initialise la base de données avec quelques données de test"""
    conn = sqlite3.connect('budget.db')
    cursor = conn.cursor()
    
    # Créer la table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            description TEXT NOT NULL,
            amount REAL NOT NULL,
            category TEXT
        )
    ''')
    
    # Vider la table si elle existe déjà
    cursor.execute('DELETE FROM transactions')
    
    # Insérer des données de test
    test_data = [
        ('Salaire mensuel', 3000.00, 'Revenu'),
        ('Courses Carrefour', -150.50, 'Alimentation'),
        ('Loyer appartement', -800.00, 'Logement'),
        ('Électricité EDF', -80.00, 'Factures'),
        ('Abonnement Netflix', -15.99, 'Loisirs'),
        ('Restaurant', -45.00, 'Alimentation'),
        ('Essence voiture', -60.00, 'Transport'),
        ('Bonus travail', 500.00, 'Revenu'),
    ]
    
    cursor.executemany(
        'INSERT INTO transactions (description, amount, category) VALUES (?, ?, ?)',
        test_data
    )
    
    conn.commit()
    conn.close()
    print("✓ Base de données initialisée avec succès")

def get_db_connection():
    """Retourne une connexion à la base de données"""
    conn = sqlite3.connect('budget.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    """Page d'accueil avec formulaires"""
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Budget App - Gestion de Budget</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 20px;
                }
                .container {
                    max-width: 800px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 15px;
                    padding: 40px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                }
                h1 {
                    color: #667eea;
                    text-align: center;
                    margin-bottom: 10px;
                    font-size: 2.5em;
                }
                .subtitle {
                    text-align: center;
                    color: #666;
                    margin-bottom: 40px;
                }
                .section {
                    background: #f8f9fa;
                    padding: 25px;
                    margin: 20px 0;
                    border-radius: 10px;
                    border-left: 4px solid #667eea;
                }
                h2 {
                    color: #333;
                    margin-bottom: 15px;
                    font-size: 1.3em;
                }
                form {
                    display: flex;
                    flex-direction: column;
                    gap: 10px;
                }
                input[type="text"], input[type="number"] {
                    padding: 12px;
                    border: 2px solid #ddd;
                    border-radius: 8px;
                    font-size: 1em;
                    transition: border-color 0.3s;
                }
                input[type="text"]:focus, input[type="number"]:focus {
                    outline: none;
                    border-color: #667eea;
                }
                button {
                    padding: 12px 25px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 1em;
                    font-weight: bold;
                    cursor: pointer;
                    transition: transform 0.2s, box-shadow 0.2s;
                }
                button:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
                }
                .link-button {
                    display: inline-block;
                    margin-top: 30px;
                    padding: 15px 30px;
                    background: #28a745;
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    text-align: center;
                    font-weight: bold;
                    transition: background 0.3s, transform 0.2s;
                }
                .link-button:hover {
                    background: #218838;
                    transform: translateY(-2px);
                }
                .emoji {
                    font-size: 1.5em;
                    margin-right: 10px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>💰 Budget App</h1>
                <p class="subtitle">Gérez votre budget facilement</p>
                
                <div class="section">
                    <h2><span class="emoji">🔍</span>Rechercher une transaction</h2>
                    <form action="/search" method="post">
                        <input type="text" name="query" placeholder="Rechercher une transaction..." required>
                        <button type="submit">Rechercher</button>
                    </form>
                </div>
                
                <div class="section">
                    <h2><span class="emoji">🧮</span>Calculer une formule</h2>
                    <form action="/calculate" method="post">
                        <input type="text" name="formula" placeholder="Ex: 100 + 50 * 2" required>
                        <button type="submit">Calculer</button>
                    </form>
                    <p style="font-size: 0.9em; color: #666; margin-top: 10px;">
                        Opérations : +, -, *, /, (), puissance avec **
                    </p>
                </div>
                
                <div class="section">
                    <h2><span class="emoji">➕</span>Ajouter une transaction</h2>
                    <form action="/add" method="post">
                        <input type="text" name="description" placeholder="Description" required>
                        <input type="number" step="0.01" name="amount" placeholder="Montant (positif=revenu, négatif=dépense)" required>
                        <input type="text" name="category" placeholder="Catégorie" required>
                        <button type="submit">Ajouter</button>
                    </form>
                </div>
                
                <center>
                    <a href="/transactions" class="link-button">
                        <span class="emoji">📋</span>Voir toutes les transactions
                    </a>
                </center>
            </div>
        </body>
        </html>
    ''')

@app.route('/search', methods=['POST'])
def search():
    """Recherche de transactions - VULNÉRABLE À L'INJECTION SQL"""
    # ❌ VULNÉRABILITÉ 2: Injection SQL
    query = request.form.get('query', '')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Construction DANGEREUSE de la requête SQL avec f-string
    sql = f"SELECT * FROM transactions WHERE description LIKE '%{query}%'"
    
    # Afficher la requête SQL dans la console (pour debug)
    print(f"[SQL QUERY] {sql}")
    
    try:
        results = cursor.execute(sql).fetchall()
        conn.close()
        
        # Construction du HTML de réponse
        html = '''
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <title>Résultats de recherche</title>
            <style>
                body { font-family: Arial; margin: 40px; background: #f5f5f5; }
                .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #667eea; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th { background: #667eea; color: white; padding: 12px; text-align: left; }
                td { padding: 12px; border-bottom: 1px solid #ddd; }
                tr:hover { background: #f8f9fa; }
                .back-link { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #28a745; color: white; text-decoration: none; border-radius: 5px; }
                .back-link:hover { background: #218838; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔍 Résultats de recherche</h1>
        '''
        
        if results:
            html += '<table><tr><th>ID</th><th>Description</th><th>Montant</th><th>Catégorie</th></tr>'
            for row in results:
                amount_color = 'green' if row['amount'] > 0 else 'red'
                html += f'<tr><td>{row["id"]}</td><td>{row["description"]}</td><td style="color: {amount_color}; font-weight: bold;">{row["amount"]} €</td><td>{row["category"]}</td></tr>'
            html += '</table>'
        else:
            html += '<p style="color: #666;">Aucun résultat trouvé.</p>'
        
        html += '<a href="/" class="back-link">← Retour</a></div></body></html>'
        return html
        
    except Exception as e:
        conn.close()
        return f'''
        <html>
        <body style="font-family: Arial; margin: 40px;">
            <div style="background: #ffebee; padding: 20px; border-radius: 10px; border-left: 4px solid #f44336;">
                <h1 style="color: #c62828;">❌ Erreur SQL</h1>
                <p style="color: #666;"><strong>Message :</strong> {str(e)}</p>
                <p style="color: #666;"><strong>Requête :</strong> <code>{sql}</code></p>
                <a href="/" style="display: inline-block; margin-top: 20px; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px;">← Retour</a>
            </div>
        </body>
        </html>
        '''

@app.route('/calculate', methods=['POST'])
def calculate():
    """Calculatrice - VULNÉRABLE À L'EXÉCUTION DE CODE ARBITRAIRE"""
    # ❌ VULNÉRABILITÉ 3: Utilisation de eval() - TRÈS DANGEREUX
    formula = request.form.get('formula', '0')
    
    try:
        # eval() exécute du code Python arbitraire !
        # Un attaquant peut faire : __import__('os').system('commande')
        result = eval(formula)
        
        return f'''
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Résultat du calcul</title>
            <style>
                body {{ font-family: Arial; margin: 40px; background: #f5f5f5; }}
                .container {{ background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                h1 {{ color: #667eea; }}
                .result {{ font-size: 2em; color: #28a745; font-weight: bold; margin: 30px 0; text-align: center; }}
                .formula {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; font-family: 'Courier New'; }}
                .back-link {{ display: inline-block; margin-top: 20px; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🧮 Résultat du calcul</h1>
                <div class="formula">
                    <strong>Formule :</strong> {formula}
                </div>
                <div class="result">= {result}</div>
                <a href="/" class="back-link">← Retour</a>
            </div>
        </body>
        </html>
        '''
    except Exception as e:
        return f'''
        <html>
        <body style="font-family: Arial; margin: 40px;">
            <div style="background: #ffebee; padding: 20px; border-radius: 10px;">
                <h1 style="color: #c62828;">❌ Erreur de calcul</h1>
                <p><strong>Formule :</strong> {formula}</p>
                <p><strong>Erreur :</strong> {str(e)}</p>
                <a href="/" style="display: inline-block; margin-top: 20px; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px;">← Retour</a>
            </div>
        </body>
        </html>
        '''

@app.route('/add', methods=['POST'])
def add_transaction():
    """Ajout d'une transaction - PAS DE PROTECTION CSRF"""
    # ❌ VULNÉRABILITÉ 4: Pas de protection CSRF
    # Un site malveillant peut soumettre ce formulaire à notre place
    
    description = request.form.get('description')
    amount = request.form.get('amount')
    category = request.form.get('category')
    
    # Validation minimale
    if not description or not amount or not category:
        return '''
        <html>
        <body style="font-family: Arial; margin: 40px;">
            <h1 style="color: #c62828;">❌ Erreur</h1>
            <p>Tous les champs sont requis !</p>
            <a href="/" style="display: inline-block; margin-top: 20px; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px;">← Retour</a>
        </body>
        </html>
        ''', 400
    
    try:
        amount_float = float(amount)
    except ValueError:
        return '''
        <html>
        <body style="font-family: Arial; margin: 40px;">
            <h1 style="color: #c62828;">❌ Erreur</h1>
            <p>Le montant doit être un nombre !</p>
            <a href="/" style="display: inline-block; margin-top: 20px; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px;">← Retour</a>
        </body>
        </html>
        ''', 400
    
    # Insérer dans la base de données
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO transactions (description, amount, category) VALUES (?, ?, ?)',
        (description, amount_float, category)
    )
    conn.commit()
    conn.close()
    
    return f'''
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: Arial; margin: 40px; background: #f5f5f5; }}
            .container {{ background: white; padding: 40px; border-radius: 10px; max-width: 600px; margin: 0 auto; text-align: center; }}
            h1 {{ color: #28a745; }}
            .details {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; text-align: left; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>✅ Transaction ajoutée avec succès !</h1>
            <div class="details">
                <p><strong>Description :</strong> {description}</p>
                <p><strong>Montant :</strong> {amount_float} €</p>
                <p><strong>Catégorie :</strong> {category}</p>
            </div>
            <a href="/" style="display: inline-block; padding: 12px 25px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px;">← Retour</a>
            <a href="/transactions" style="display: inline-block; padding: 12px 25px; background: #28a745; color: white; text-decoration: none; border-radius: 5px; margin: 10px;">Voir toutes les transactions</a>
        </div>
    </body>
    </html>
    '''

@app.route('/transactions')
def transactions():
    """Affiche toutes les transactions"""
    conn = get_db_connection()
    transactions = conn.execute('SELECT * FROM transactions ORDER BY id DESC').fetchall()
    conn.close()
    
    # Calculer le solde total
    total = sum(t['amount'] for t in transactions)
    
    html = '''
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Toutes les transactions</title>
        <style>
            body { font-family: Arial; margin: 40px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
            .container { background: white; padding: 40px; border-radius: 15px; max-width: 1000px; margin: 0 auto; box-shadow: 0 10px 40px rgba(0,0,0,0.2); }
            h1 { color: #667eea; text-align: center; }
            .summary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin: 20px 0; text-align: center; }
            .summary h2 { margin: 0; font-size: 2em; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th { background: #667eea; color: white; padding: 15px; text-align: left; }
            td { padding: 12px; border-bottom: 1px solid #ddd; }
            tr:hover { background: #f8f9fa; }
            .positive { color: #28a745; font-weight: bold; }
            .negative { color: #dc3545; font-weight: bold; }
            .back-link { display: inline-block; margin-top: 20px; padding: 12px 25px; background: #28a745; color: white; text-decoration: none; border-radius: 8px; font-weight: bold; }
            .back-link:hover { background: #218838; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📋 Toutes vos transactions</h1>
    '''
    
    html += f'''
            <div class="summary">
                <h2>Solde total : {total:.2f} €</h2>
            </div>
    '''
    
    if transactions:
        html += '<table><tr><th>ID</th><th>Description</th><th>Montant</th><th>Catégorie</th></tr>'
        for row in transactions:
            amount_class = 'positive' if row['amount'] > 0 else 'negative'
            html += f'<tr><td>#{row["id"]}</td><td>{row["description"]}</td><td class="{amount_class}">{row["amount"]:.2f} €</td><td>{row["category"]}</td></tr>'
        html += '</table>'
    else:
        html += '<p style="text-align: center; color: #666;">Aucune transaction enregistrée.</p>'
    
    html += '<center><a href="/" class="back-link">← Retour à laccueil</a></center></div></body></html>'
    return html

if __name__ == '__main__':
    # Créer/réinitialiser la base de données au démarrage
    if not os.path.exists('budget.db'):
        print("Création de la base de données...")
        init_db()
    else:
        # Réinitialiser à chaque démarrage pour les tests
        print("Réinitialisation de la base de données...")
        init_db()
    
    print("\n" + "="*50)
    print("🚀 Application Flask Budget App démarrée !")
    print("="*50)
    print("📍 URL : http://localhost:5000")
    print("⚠️  ATTENTION : Cette version contient des vulnérabilités volontaires")
    print("="*50 + "\n")
    
    # ❌ VULNÉRABILITÉ 5: Debug mode activé (expose des infos sensibles en cas d'erreur)
    app.run(debug=True, host='0.0.0.0', port=5000)
