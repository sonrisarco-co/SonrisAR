from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sonrisar.db'
app.config['SECRET_KEY'] = 'sonrisar_secret_key'
app.config['JWT_SECRET_KEY'] = 'sonrisar_jwt_secret_key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=8)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Modelos
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Paciente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombres = db.Column(db.String(100), nullable=False)
    apellidos = db.Column(db.String(100), nullable=False)
    cedula = db.Column(db.String(20))
    telefono = db.Column(db.String(20))
    direccion = db.Column(db.String(150))
    observaciones = db.Column(db.Text)

class Consulta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    paciente_id = db.Column(db.Integer, db.ForeignKey('paciente.id'), nullable=False)
    fecha = db.Column(db.String(20))
    motivo = db.Column(db.String(200))
    diagnostico = db.Column(db.String(200))
    tratamiento = db.Column(db.String(200))
    notas = db.Column(db.Text)

@app.before_first_request
def crear_admin():
    db.create_all()
    if not Usuario.query.filter_by(usuario='admin').first():
        hashed = bcrypt.generate_password_hash('admin').decode('utf-8')
        db.session.add(Usuario(usuario='admin', password=hashed))
        db.session.commit()

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def do_login():
    data = request.form
    usuario = Usuario.query.filter_by(usuario=data['usuario']).first()
    if usuario and bcrypt.check_password_hash(usuario.password, data['password']):
        session['usuario'] = usuario.usuario
        return redirect(url_for('pacientes'))
    return render_template('login.html', error='Usuario o contraseña incorrectos')

@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect(url_for('login'))

@app.route('/pacientes')
def pacientes():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    lista = Paciente.query.all()
    return render_template('pacientes.html', pacientes=lista)

@app.route('/paciente/nuevo', methods=['POST'])
def nuevo_paciente():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    p = Paciente(
        nombres=request.form['nombres'],
        apellidos=request.form['apellidos'],
        cedula=request.form.get('cedula'),
        telefono=request.form.get('telefono'),
        direccion=request.form.get('direccion'),
        observaciones=request.form.get('observaciones')
    )
    db.session.add(p)
    db.session.commit()
    return redirect(url_for('pacientes'))

@app.route('/paciente/<int:id>')
def ficha(id):
    if 'usuario' not in session:
        return redirect(url_for('login'))
    paciente = Paciente.query.get_or_404(id)
    consultas = Consulta.query.filter_by(paciente_id=id).all()
    return render_template('ficha.html', paciente=paciente, consultas=consultas)

@app.route('/consulta/nueva/<int:id>', methods=['POST'])
def nueva_consulta(id):
    if 'usuario' not in session:
        return redirect(url_for('login'))
    c = Consulta(
        paciente_id=id,
        fecha=request.form['fecha'],
        motivo=request.form['motivo'],
        diagnostico=request.form['diagnostico'],
        tratamiento=request.form['tratamiento'],
        notas=request.form.get('notas')
    )
    db.session.add(c)
    db.session.commit()
    return redirect(url_for('ficha', id=id))

@app.route('/paciente/<int:id>/pdf')
def exportar_pdf(id):
    paciente = Paciente.query.get_or_404(id)
    consultas = Consulta.query.filter_by(paciente_id=id).all()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elems = []

    logo_path = os.path.join('static', 'logo.jpg')
    if os.path.exists(logo_path):
        elems.append(RLImage(logo_path, width=100, height=100))
    elems.append(Paragraph('<b>SonrisAR – Centro Odontológico</b>', styles['Title']))
    elems.append(Paragraph('Dr. Sebastián Rodrigo Suma Britos', styles['Normal']))
    elems.append(Paragraph('Román Guerra 752 – Tel. 092706293', styles['Normal']))
    elems.append(Spacer(1, 12))
    elems.append(Paragraph(f'<b>Paciente:</b> {paciente.nombres} {paciente.apellidos}', styles['Normal']))
    elems.append(Paragraph(f'<b>Cédula:</b> {paciente.cedula or "-"}', styles['Normal']))
    elems.append(Paragraph(f'<b>Teléfono:</b> {paciente.telefono or "-"}', styles['Normal']))
    elems.append(Paragraph(f'<b>Dirección:</b> {paciente.direccion or "-"}', styles['Normal']))
    elems.append(Spacer(1, 12))
    elems.append(Paragraph('<b>Consultas:</b>', styles['Heading2']))
    for c in consultas:
        elems.append(Paragraph(f'Fecha: {c.fecha}', styles['Normal']))
        elems.append(Paragraph(f'Motivo: {c.motivo}', styles['Normal']))
        elems.append(Paragraph(f'Diagnóstico: {c.diagnostico}', styles['Normal']))
        elems.append(Paragraph(f'Tratamiento: {c.tratamiento}', styles['Normal']))
        elems.append(Paragraph(f'Notas: {c.notas or ""}', styles['Normal']))
        elems.append(Spacer(1, 10))
    doc.build(elems)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"ficha_{paciente.id}.pdf", mimetype='application/pdf')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
