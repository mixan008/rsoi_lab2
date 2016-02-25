from API import db, Marks, Car_model
import random

db.drop_all()
db.create_all()

marks_and_car_models = [
    ['Accord','Honda'],
    ['Civic', 'Honda'],
    ['Pilot', 'Honda'],
    ['Lancer','Mitsibishi'],
    ['Eclipse','Mitsibishi'],
    ['Colt','Mitsibishi'],
    ['Pagero','Mitsibishi'],
    ['Challenger','Mitsibishi'],
    ['Sentra','Nissan'],
    ['Almera','Nissan'],
    ['Teana','Nissan'],
    ['Skyline','Nisan'],
    ['Camaro','Chevrolet'],
    ['Tahoe','Chevrolet'],
    ['Chevelle','Chevrolet'],
    ['Astra','Chevrolet'],
    ['Cobalt','Chevrolet'],
    ['Challenger','Dodge'],
    ['Charger','Dodge'],
    ['Neon','Dodge'],
    ['Caliber','Dodge'],
    ['Avenger','Dodge'],
    ['Celica','Toyota'],
    ['Prius','Toyota'],
    ['Land Cruiser','Toyota'],
    ['Fiesta','Ford'],
    ['Focus','Ford'],
    ['Mondeo','Ford'],
    ['Mustang','Ford'],
    ['Astra','Opel'],
    ['Omega','Opel'],
    ['Vectra','Opel'],
    ['Antara','Opel'],
    ['Polo','Volkswagen'],
    ['Passat','Volkswagen'],
    ['Jetta','Volkswagen'],
    ['Golf','Volkswagen']

]

random.shuffle(marks_and_car_models)

for q in marks_and_car_models:
    r = Marks.query.filter_by(name=q[1]).first()
    if r is None:
        r1 = Marks(name=q[1])
        qq = Car_model(car_model=q[0], mark=r1)
    else:
        qq = Car_model(car_model=q[0], mark_id=r.id)
    db.session.add(qq)
    db.session.commit()

