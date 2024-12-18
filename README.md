## Project Name
### Sneakers Store

## Project Description
SneakersStore is a simple yet effective web application designed to streamline team management and collaboration. It enables users to perform full CRUD operations (Create, Read, Update, Delete) on product and inventory data, such as sneaker models, prices, and stock, through an intuitive interface.

### Purpose
Simplify the management of sneaker sales and inventory.  
Help small businesses keep track of products effectively.

### Key Features
- Product Management: Add, view, update, and delete sneaker details.
- Easy Collaboration: Designed for small businesses and collaborative sales teams.
- Fast and Scalable: Backend powered by Golang with MongoDB for database storage.

## Target Audience
- Small businesses managing product inventories.
- Developers learning CRUD operations and full-stack development.
- Teams seeking a simple product management tool.

## Team Members
| Name   | Role               |
|--------|--------------------|
| Daniil | Super Duper Ultra Team Lead |
| Zhannur| Gachi master Developer  |
| Adil   | Awesome Developer  |

## Screenshot of Main Page
(Add an actual screenshot of the main webpage in the assets folder.)

## How to Start the Project
### Prerequisites
- Golang installed.
- MongoDB running locally or in the cloud.
- A browser to view the HTML frontend.

### Steps to Start
1. Clone the Repository
```bash
git clone https://github.com/your-team/sneakers-store.git
cd sneakers-store
```
2. Run the Backend Server

Ensure MongoDB is running locally at mongodb://localhost:27017.  
Start the Go server:
```bash
go run main.go
```
The server will be available at: http://localhost:8080.

3. Serve the Frontend

Use a local HTTP server to serve the `crud.html` file:
```bash
cd frontend
python3 -m http.server 8000
```
Open your browser and visit: http://localhost:8000.

## Tools and Technologies Used
| Tool      | Purpose                             |
|-----------|-------------------------------------|
| Golang    | Backend server                     |
| MongoDB   | Database for storing user data     |
| HTML/CSS/JS| Frontend for user interaction      |
| Postman   | API testing                        |
| GitHub    | Version control and hosting        |

## Repository Structure
```
sneakers-store/
├── backend/
│   ├── main.go             # Main server file
│   ├── db/
│   │   ├── mongo.go        # MongoDB connection
│   │   ├── users.go         # CRUD operations
│   └── go.mod              # Go module dependencies
├── frontend/
│   ├── index.html           # Main frontend file
├── README.md               # Project documentation
```

## Public Repository
This project is publicly available at:  
👉 [https://github.com/ZhannurK/Online-Shop.git](https://github.com/ZhannurK/Online-Shop.git)

## Thank You for Checking Out Our Project!
Feel free to reach out or open an issue if you encounter any problems or want to contribute. Let's make inventory management better together!
