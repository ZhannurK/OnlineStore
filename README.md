## PULLO
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
![image](https://github.com/user-attachments/assets/7a1e62d9-817b-412a-a53a-6b12a04eb2fc)


## How to Start the Project
### Prerequisites
- Golang installed.
- MongoDB running locally or in the cloud.
- A browser to view the HTML frontend.

### Steps to Start
1. Clone the Repository
```bash
git clone https://github.com/ZhannurK/OnlineStore.git
cd OnlineStore
```
2. Run the Backend Server

Ensure MongoDB is running locally at mongodb://localhost:27017.  
Start the Go server:
```bash
go run main.go
```
The server will be available at: http://localhost:8080.

```
Open your browser and visit: http://localhost:8000.

## Tools and Technologies Used
| Tool       | Purpose                             |
|------------|-------------------------------------|
| Golang     | Backend server                      |
| MongoDB    | Database for storing user data      |
| HTML/CSS/JS| Frontend for user interaction       |
| Postman    | API testing                         |
| GitHub     | Version control and hosting         |
```

## Repository Structure
```
OnlineStore/
├── main.go                 # Main server file
├── main_test.go            # Three types of tests of main.go file
├── chat/
│   ├── chat.go             # support functions nad handlers
│   ├── db/
│   │   ├── mongo.go        # MongoDB connection
│   │   ├── users.go        # CRUD operations
│   └── go.mod              # Go module dependencies
├── store/                  # frontend files
│   ├── store.html          # home page
|   ├── ...
├── README.md               # Project documentation
```

## Public Repository
This project is publicly available at:  
👉 https://github.com/ZhannurK/Online-Shop

## Deploy of the project
here you can see the project without downloading it 👉 https://onlinestore-production-d843.up.railway.app

## Thank You for Checking Out Our Project!
Feel free to reach out or open an issue if you encounter any problems or want to contribute. Let's make online sales better together!
