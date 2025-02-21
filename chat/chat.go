package chat

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var chatClients = make(map[*websocket.Conn]string) // WebSocket-клиенты
var mutex sync.Mutex
var db *mongo.Client

// Инициализация MongoDB
func InitMongoDB(mongoClient *mongo.Client) {
	db = mongoClient
}

// Создание нового чата
func CreateChatHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		http.Error(w, "Missing client ID", http.StatusBadRequest)
		return
	}

	collection := db.Database("db").Collection("chats")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var existingChat bson.M
	err := collection.FindOne(ctx, bson.M{"chat_id": clientID, "status": "active"}).Decode(&existingChat)
	if err == nil {
		resp := map[string]string{"message": "У вас уже есть активный чат"}
		jsonResp, _ := json.Marshal(resp)
		w.Write(jsonResp)
		return
	}

	chat := bson.M{
		"chat_id":  clientID,
		"messages": []bson.M{},
		"status":   "active",
	}

	_, err = collection.InsertOne(ctx, chat)
	if err != nil {
		http.Error(w, "Ошибка создания чата", http.StatusInternalServerError)
		return
	}

	resp2 := map[string]string{"message": "Чат создан"}
	jsonResp2, _ := json.Marshal(resp2)
	w.Write(jsonResp2)
}

// WebSocket-обработчик
func ChatHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Ошибка WebSocket:", err)
		return
	}
	defer ws.Close()

	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		log.Println("Не указан client ID")
		return
	}

	// **Если это админ, то он подключается к активному чату пользователя**
	if clientID == "admin" {
		clientID = r.URL.Query().Get("chat_id") // Админ должен выбрать, с кем общается
	}

	mutex.Lock()
	chatClients[ws] = clientID
	mutex.Unlock()

	log.Println("Новое соединение с клиентом:", clientID)

	// **Отправляем историю сообщений**
	sendChatHistory(ws, clientID)

	for {
		var msg struct {
			Sender  string `json:"sender"`
			Content string `json:"content"`
		}

		err := ws.ReadJSON(&msg)
		if err != nil {
			log.Println("Ошибка чтения JSON:", err)
			break
		}

		saveMessage(clientID, msg.Sender, msg.Content)
		broadcastMessage(clientID, msg)
	}

	mutex.Lock()
	delete(chatClients, ws)
	mutex.Unlock()
}

// Закрытие чата администратором
func DeleteChatHandler(w http.ResponseWriter, r *http.Request) {
	chatID := r.URL.Query().Get("chat_id")
	if chatID == "" {
		http.Error(w, "Missing chat_id", http.StatusBadRequest)
		return
	}

	collection := db.Database("db").Collection("chats")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := collection.DeleteOne(ctx, bson.M{"chat_id": chatID})
	if err != nil {
		http.Error(w, "Ошибка удаления чата", http.StatusInternalServerError)
		return
	}

	// Удаляем WebSocket-соединения
	mutex.Lock()
	for conn, clientID := range chatClients {
		if clientID == chatID {
			conn.Close()
			delete(chatClients, conn)
		}
	}
	mutex.Unlock()

	w.Write([]byte(`{"message": "Чат удалён"}`))
}

func sendChatHistory(ws *websocket.Conn, chatID string) {
	collection := db.Database("db").Collection("chats")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var chat struct {
		Messages []bson.M `bson:"messages"`
	}

	err := collection.FindOne(ctx, bson.M{"chat_id": chatID}).Decode(&chat)
	if err != nil {
		log.Println("Ошибка загрузки истории сообщений:", err)
		return
	}

	for _, message := range chat.Messages {
		err := ws.WriteJSON(message)
		if err != nil {
			log.Println("Ошибка отправки истории сообщений:", err)
			return
		}
	}
}

// Сохранение сообщения в MongoDB
func saveMessage(chatID, sender, content string) {
	if db == nil {
		log.Println("MongoDB не инициализирован")
		return
	}

	collection := db.Database("db").Collection("chats")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	message := bson.M{
		"sender":    sender,
		"content":   content,
		"timestamp": time.Now(),
	}

	update := bson.M{
		"$push": bson.M{"messages": message},
		"$setOnInsert": bson.M{
			"chat_id": chatID,
			"status":  "active",
		},
	}

	_, err := collection.UpdateOne(ctx, bson.M{"chat_id": chatID}, update, options.Update().SetUpsert(true))
	if err != nil {
		log.Println("Ошибка сохранения сообщения:", err)
	}
}

// Отправка сообщения только в нужный чат
func broadcastMessage(chatID string, msg interface{}) {
	mutex.Lock()
	defer mutex.Unlock()

	for conn, clientChatID := range chatClients {
		if clientChatID == chatID {
			err := conn.WriteJSON(msg)
			if err != nil {
				log.Println("Ошибка отправки сообщения:", err)
				conn.Close()
				delete(chatClients, conn)
			}
		}
	}
}
