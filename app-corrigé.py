import os
from flask import Flask, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, FloatField, SubmitField
from wtforms.validators import DataRequired, Length
import ast
import operator

app = Flask(__name__)

# ✅ SÉCURITÉ : Chargement des secrets depuis l'environnement
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'un-secret-par-defaut-tres-long-pour-le-dev')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///budget.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ✅ SÉCURITÉ : Activation de la protection CSRF globale
csrf = CSRFProtect(app)
db = SQLAlchemy(app)

# Modèle de données sécurisé
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)

# ✅ SÉCURITÉ : Utilisation de formulaires WTForms pour la validation
class TransactionForm(FlaskForm):
    description = StringField('Description', validators=[DataRequired(), Length(max=100)])
    amount = FloatField('Montant', validators=[DataRequired()])
    category = StringField('Catégorie', validators=[DataRequired(), Length(max=50)])
    submit = SubmitField('Ajouter')

# ✅ SÉCURITÉ : Parseur de calcul sûr (remplace eval())
def safe_eval(expr):
    allowed_operators = {
        ast.Add: operator.add, ast.Sub: operator.sub, 
        ast.Mult: operator.mul, ast.Div: operator.truediv, 
        ast.Pow: operator.pow, ast.USub: operator.neg
    }
    
    def eval_node(node):
        if isinstance(node, ast.Num): return node.n
        elif isinstance(node, ast.BinOp):
            return allowed_operators[type(node.op)](eval_node(node.left), eval_node(node.right))
        elif isinstance(node, ast.UnaryOp):
            return allowed_operators[type(node.op)](eval_node(node.operand))
        else: raise TypeError(node)

    return eval_node(ast.parse(expr, mode='eval').body)

@app.route('/')
def index():
    form = TransactionForm()
    return render_template('index.html', form=form)

@app.route('/search', methods=['POST'])
def search():
    # ✅ SÉCURITÉ : Requête paramétrée via l'ORM (évite l'injection SQL)
    query = request.form.get('query', '')
    results = Transaction.query.filter(Transaction.description.contains(query)).all()
    return render_template('results.html', results=results)

@app.route('/calculate', methods=['POST'])
def calculate():
    # ✅ SÉCURITÉ : Utilisation du parseur AST (évite l'exécution de code arbitraire)
    formula = request.form.get('formula', '0')
    try:
        result = safe_eval(formula)
        return render_template('calc_result.html', result=result, formula=formula)
    except Exception as e:
        flash(f"Erreur de calcul : {str(e)}", "danger")
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
        flash("✅ Transaction ajoutée !", "success")
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # ✅ SÉCURITÉ : Debug désactivé et host restreint par défaut
    app.run(debug=False)
