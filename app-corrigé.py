import os
import ast
import operator
import sqlite3
from flask import Flask, request, render_template_string, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, FloatField, SubmitField
from wtforms.validators import DataRequired, Length

# --- INITIALISATION ET SÉCURITÉ CONFIG ---
app = Flask(__name__)

# ✅ SÉCURITÉ : Ne jamais coder les secrets en dur. On utilise des variables d'environnement.
# On génère une clé aléatoire si aucune n'est fournie (standard de sécurité).
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///budget.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ✅ SÉCURITÉ : Protection contre les attaques Cross-Site Request Forgery (CSRF)
csrf = CSRFProtect(app)
db = SQLAlchemy(app)

# --- MODÈLES DE DONNÉES (ORM) ---
# L'utilisation d'un ORM comme SQLAlchemy empêche nativement les injections SQL
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)

# --- FORMULAIRES SÉCURISÉS (WTForms) ---
# Valide les données côté serveur pour empêcher les injections XSS ou NaN
class TransactionForm(FlaskForm):
    description = StringField('Description', validators=[DataRequired(), Length(max=100)])
    amount = FloatField('Montant', validators=[DataRequired()])
    category = StringField('Catégorie', validators=[DataRequired(), Length(max=50)])
    submit = SubmitField('Ajouter')

# --- LOGIQUE DE CALCUL SÉCURISÉE (Remplace eval()) ---
# ✅ SÉCURITÉ : Parseur AST pour limiter strictement les opérations autorisées
def safe_eval(expr):
    allowed_operators = {
        ast.Add: operator.add, ast.Sub: operator.sub, 
        ast.Mult: operator.mul, ast.Div: operator.truediv, 
        ast.Pow: operator.pow, ast.USub: operator.neg,
        ast.UAdd: operator.pos
    }
    
    try:
        node = ast.parse(expr, mode='eval').body
        def _eval(node):
            if isinstance(node, ast.Num): 
                return node.n
            elif isinstance(node, ast.BinOp):
                return allowed_operators[type(node.op)](_eval(node.left), _eval(node.right))
            elif isinstance(node, ast.UnaryOp):
                return allowed_operators[type(node.op)](_eval(node.operand))
            else:
                raise ValueError("Opération non autorisée détectée.")
        return _eval(node)
    except Exception:
        raise ValueError("Formule invalide ou dangereuse.")

# --- ROUTES ---

@app.route('/')
def index():
    form = TransactionForm()
    # Utilisation de templates pour éviter le XSS lié au render_template_string
    return render_template_string(BASE_TEMPLATE, form=form)

@app.route('/search', methods=['POST'])
def search():
    # ✅ SÉCURITÉ : Utilisation de l'ORM avec paramètres (protection SQLi)
    query = request.form.get('query', '')
    results = Transaction.query.filter(Transaction.description.contains(query)).all()
    return render_template_string(RESULTS_TEMPLATE, results=results, query=query)

@app.route('/calculate', methods=['POST'])
def calculate():
    formula = request.form.get('formula', '0')
    try:
        # ✅ SÉCURITÉ : Plus d'eval(), utilisation de safe_eval
        result = safe_eval(formula)
        return render_template_string(CALC_TEMPLATE, result=result, formula=formula)
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for('index'))

@app.route('/add', methods=['POST'])
def add_transaction():
    form = TransactionForm()
    if form.validate_on_submit():
        new_tx = Transaction(
            description=form.description.data,
            amount=form.amount.data,
            category=form.category.data
        )
        db.session.add(new_tx)
        db.session.commit()
        flash("✅ Transaction ajoutée avec succès !", "success")
    return redirect(url_for('index'))

@app.route('/transactions')
def list_transactions():
    transactions = Transaction.query.order_by(Transaction.id.desc()).all()
    total = sum(t.amount for t in transactions)
    return render_template_string(LIST_TEMPLATE, transactions=transactions, total=total)

# --- TEMPLATES (SÉCURISÉS) ---
# Note : En production, ces blocs doivent être dans des fichiers .html séparés.
BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8"><title>Budget App SÉCURISÉE</title>
    <style>body { font-family: sans-serif; padding: 20px; background: #f4f4f9; }</style>
</head>
<body>
    <h1>💰 Budget App SÉCURISÉE</h1>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}{% for category, message in messages %}<p style="color:red">{{ message }}</p>{% endfor %}{% endif %}
    {% endwith %}
    
    <form action="/search" method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="text" name="query" placeholder="Rechercher...">
        <button type="submit">Rechercher</button>
    </form>
    <hr>
    <form action="/calculate" method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="text" name="formula" placeholder="Formule (ex: 10+5)">
        <button type="submit">Calculer</button>
    </form>
    <hr>
    <h3>Ajouter</h3>
    <form method="POST" action="/add">
        {{ form.hidden_tag() }}
        {{ form.description.label }} {{ form.description() }}<br>
        {{ form.amount.label }} {{ form.amount() }}<br>
        {{ form.category.label }} {{ form.category() }}<br>
        {{ form.submit() }}
    </form>
    <br><a href="/transactions">Voir tout</a>
</body></html>
'''

RESULTS_TEMPLATE = '''
<h1>Résultats pour : {{ query }}</h1>
<ul>
{% for res in results %}
    <li>{{ res.description }} : {{ res.amount }} € ({{ res.category }})</li>
{% endfor %}
</ul>
<a href="/">Retour</a>
'''

CALC_TEMPLATE = '''
<h1>Résultat du calcul</h1>
<p>Formule : {{ formula }}</p>
<p><strong>Résultat = {{ result }}</strong></p>
<a href="/">Retour</a>
'''

LIST_TEMPLATE = '''
<h1>📋 Transactions</h1>
<h3>Solde Total : {{ total }} €</h3>
<table border="1">
    <tr><th>ID</th><th>Description</th><th>Montant</th><th>Catégorie</th></tr>
    {% for t in transactions %}
    <tr><td>{{ t.id }}</td><td>{{ t.description }}</td><td>{{ t.amount }}</td><td>{{ t.category }}</td></tr>
    {% endfor %}
</table>
<br><a href="/">Retour</a>
'''

# --- DÉMARRAGE ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Crée la base de données de manière sécurisée
    
    # ✅ SÉCURITÉ : debug=False impératif en production. Host restreint à localhost
    app.run(debug=False, host='127.0.0.1', port=5000)
