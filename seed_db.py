import os
import random
import string
from getpass import getpass
from passlib.hash import pbkdf2_sha256
from faker import Faker
from app import create_app
from models import db, Employee
from flask_mail import Message, Mail

fake = Faker()
app = create_app()

EMPLOYEE_PREFIX = 'UAP'

def gen_employee_id(i, start=1001):
    return f"{EMPLOYEE_PREFIX}{start + i}"

def gen_password(length=12):
    chars = string.ascii_letters + string.digits + '!@#$%&*()'
    return ''.join(random.choice(chars) for _ in range(length))

def confirm(prompt='Continue? (y/n): '):
    ans = input(prompt).strip().lower()
    return ans in ('y','yes')

def send_credentials(mail, to_email, name, employee_id, password):
    try:
        msg = Message('Your Account Credentials', recipients=[to_email])
        msg.body = f"""Hello {name},

Your account for Unified Academic Platform has been created.

Employee ID: {employee_id}
Temporary Password: {password}

Please login and reset your password immediately.

-- Admin
"""
        mail.send(msg)
        return True
    except Exception as e:
        print('Failed to send email:', e)
        return False

def run_seed():
    with app.app_context():
        mail = Mail(app)
        db.create_all()
        print("Interactive employee seeding. You will enter details for each employee.")
        count = input("How many employees do you want to enter? (default 10): ").strip()
        try:
            total = int(count) if count else 10
        except:
            total = 10

        for i in range(total):
            print(f"\n--- Employee {i+1} of {total} ---")
            name = input("Full name: ").strip()
            contact = input("Contact (10 digits): ").strip()
            while len(contact) != 10 or not contact.isdigit():
                contact = input("Invalid. Contact (10 digits): ").strip()

            department = input("Department: ").strip() or fake.job()
            email = input("Email (unique): ").strip()
            address = input("Address: ").strip() or fake.address().replace('\n', ', ')
            aadhaar = input("Aadhaar (12 digits): ").strip()
            while len(aadhaar) != 12 or not aadhaar.isdigit():
                aadhaar = input("Invalid. Aadhaar (12 digits): ").strip()

            pan = input("PAN (10 chars): ").strip().upper()
            # small PAN validation (not exhaustive)
            while len(pan) != 10:
                pan = input("Invalid. PAN (10 chars): ").strip().upper()

            dob = input("DOB (YYYY-MM-DD): ").strip()
            age = input("Age (number): ").strip()
            try:
                age = int(age)
            except:
                age = None

            photo = input("Photo path or leave blank: ").strip() or None

            emp_id = gen_employee_id(i)
            raw_pass = gen_password()
            pw_hash = pbkdf2_sha256.hash(raw_pass)

            emp = Employee(
                name=name,
                contact=contact,
                department=department,
                email=email,
                address=address,
                aadhaar=aadhaar,
                pan=pan,
                dob=dob,
                age=age,
                employee_id=emp_id,
                password_hash=pw_hash,
                photo=photo
            )

            db.session.add(emp)
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print("Failed to add employee to DB:", e)
                print("Skipping this entry.")
                continue

            sent = send_credentials(mail, email, name, emp_id, raw_pass)
            print(f"Created: {emp_id} | {email} | password_sent={sent}")

        print("Seeding complete.")

if __name__ == '__main__':
    run_seed()
