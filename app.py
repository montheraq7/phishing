from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import pickle
import re
import string
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)
CORS(app)

# Load the trained model
model = None
try:
    with open('phishing_model.pkl', 'rb') as f:
        model = pickle.load(f)
    print("✅ Model loaded successfully!")
    print(f"Model type: {type(model)}")
except FileNotFoundError:
    print("⚠️ Warning: phishing_model.pkl not found.")
except Exception as e:
    print(f"⚠️ Error loading model: {e}")

# Text preprocessing (same as training)
def preprocess_text(text):
    """Clean and preprocess email text"""
    text = text.lower()
    text = re.sub(r'http\S+|www\S+|https\S+', '', text)
    text = re.sub(r'\S+@\S+', '', text)
    text = re.sub(r'<.*?>', '', text)
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    text = ' '.join(text.split())
    return text

@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_email():
    """Analyze email for phishing detection using ML model"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'لم يتم استلام بيانات'}), 400
        
        subject = data.get('subject', '')
        body = data.get('body', '')
        
        if not subject and not body:
            return jsonify({'error': 'الرجاء إدخال موضوع أو محتوى الإيميل'}), 400
        
        # Combine subject and body
        full_email = f"{subject} {body}"
        
        # Preprocess
        processed_email = preprocess_text(full_email)
        
        # Use ML model if available
        if model is not None:
            try:
                # Get prediction
                prediction = model.predict([processed_email])[0]
                proba = model.predict_proba([processed_email])[0]
                
                is_phishing = bool(prediction == 1)
                confidence_score = max(proba)
                
                # Map confidence to Arabic
                if confidence_score >= 0.9:
                    confidence = "عالية جداً"
                elif confidence_score >= 0.75:
                    confidence = "عالية"
                elif confidence_score >= 0.6:
                    confidence = "متوسطة"
                else:
                    confidence = "منخفضة"
                
                # Extract warning signs
                warning_signs = []
                text_lower = full_email.lower()
                
                if 'verify' in text_lower or 'confirm' in text_lower or 'تأكيد' in full_email or 'تحديث' in full_email:
                    warning_signs.append("طلب التحقق من البيانات الشخصية")
                if 'urgent' in text_lower or 'immediately' in text_lower or 'عاجل' in full_email or 'فوري' in full_email:
                    warning_signs.append("استخدام لغة الاستعجال والضغط")
                if re.search(r'click\s+(here|link)', text_lower) or 'اضغط هنا' in full_email:
                    warning_signs.append("طلب النقر على روابط مشبوهة")
                if 'password' in text_lower or 'كلمة المرور' in full_email or 'كلمة السر' in full_email:
                    warning_signs.append("طلب معلومات حساسة")
                if re.search(r'http[s]?://', full_email):
                    warning_signs.append("يحتوي على روابط خارجية")
                if 'account' in text_lower or 'حساب' in full_email:
                    warning_signs.append("يتعلق بمعلومات الحساب")
                if 'prize' in text_lower or 'winner' in text_lower or 'جائزة' in full_email:
                    warning_signs.append("وعود بجوائز أو مكاسب")
                
                if not warning_signs:
                    warning_signs = ["لم يتم اكتشاف علامات تحذير واضحة"]
                
                # Generate reason
                if is_phishing:
                    reason = f"نموذج الذكاء الاصطناعي يتوقع أن هذا إيميل تصيد احتيالي بدرجة ثقة {confidence_score:.1%}"
                else:
                    reason = f"نموذج الذكاء الاصطناعي يتوقع أن هذا إيميل آمن بدرجة ثقة {confidence_score:.1%}"
                
                return jsonify({
                    'is_phishing': is_phishing,
                    'confidence': confidence,
                    'reason': reason,
                    'warning_signs': warning_signs,
                    'ml_confidence': f"{confidence_score:.1%}",
                    'model_used': 'ML Model (Naive Bayes)'
                })
                
            except Exception as e:
                print(f"ML prediction error: {e}")
                # Fall back to keyword-based detection
                pass
        
        # Fallback: Keyword-based detection
        phishing_keywords = [
            'verify account', 'suspended account', 'click here immediately',
            'confirm your password', 'update payment', 'urgent action',
            'verify your identity', 'unusual activity', 'limited time'
        ]
        
        text_lower = full_email.lower()
        phishing_score = sum(1 for keyword in phishing_keywords if keyword in text_lower)
        
        is_phishing = phishing_score >= 2
        confidence = "عالية" if phishing_score >= 3 else "متوسطة" if phishing_score >= 1 else "منخفضة"
        
        warning_signs = ["تحليل بسيط باستخدام الكلمات المفتاحية"]
        reason = f"تم اكتشاف {phishing_score} مؤشرات للتصيد" if is_phishing else "لا توجد مؤشرات واضحة للتصيد"
        
        return jsonify({
            'is_phishing': is_phishing,
            'confidence': confidence,
            'reason': reason,
            'warning_signs': warning_signs,
            'model_used': 'Keyword-based (Fallback)'
        })
        
    except Exception as e:
        print(f"Error in analyze_email: {str(e)}")
        return jsonify({'error': f'حدث خطأ في التحليل: {str(e)}'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'running',
        'model_loaded': model is not None
    })

if __name__ == '__main__':
    import os
    print("Starting Phishing Email Detection API...")
    print(f"Model loaded: {model is not None}")
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
