from website import create_app, db
from website.models import User

# Create the Flask app and set up the application context
app = create_app()
app.app_context().push()

# Fetch all users
users = User.query.all()

for user in users:
    # Update the user records here
    # Assuming user.password already contains hashed passwords as bytes

    # Commit the changes to the database
db.session.commit()

# Pop the application context
app.app_context().pop()
