
const admin = require("firebase-admin");
const serviceAccount = require("./firebaseConfig.json"); 

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://securityproyect-3b121.firebaseio.com" 
});

const db = admin.firestore();
module.exports = { admin, db };   