import app from "./app.js";

const PORT = Number(process.env.PORT || 4000);

// 1. ADD THIS: Log every incoming request to see if they reach the server
app.use((req, res, next) => {
  console.log(`Incoming Request: ${req.method} ${req.url}`);
  next();
});

// ... your routes are effectively imported inside 'app' above ...

// 2. THE ERROR HANDLER (Must be after routes)
app.use((err, req, res, next) => {
  console.error("!!! RENDER SERVER ERROR !!!");
  console.error("Message:", err.message);
  console.error("Stack:", err.stack);
  res.status(500).json({ 
    error: "Internal Server Error", 
    debugMessage: err.message 
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});