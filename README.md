# PhishBreaker - AI-Powered Phishing Detection System

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-green)
![Machine Learning](https://img.shields.io/badge/ML-Random%20Forest-orange)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API%20Integration-red)

PhishBreaker is a sophisticated phishing detection system that combines machine learning algorithms with threat intelligence to provide real-time URL safety analysis. The system uses a Random Forest classifier trained on the Phishtank dataset and enriches predictions with VirusTotal reputation data.

## 🚀 Features

- **AI-Powered Detection**: Random Forest classifier with 300 estimators
- **Real-time Analysis**: Instant URL safety scoring (0-100 scale)
- **Threat Intelligence**: VirusTotal API integration for reputation checking
- **Network Analysis**: DNS, SSL, WHOIS, and HTTP header analysis
- **Web Interface**: Modern, responsive Flask-based dashboard
- **Feature Engineering**: 15+ URL-based and network features
- **Prediction Logging**: Comprehensive logging for analysis and improvement

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Interface │    │  ML Prediction   │    │  Threat Intel   │
│  (Flask + HTML) │────│   Engine         │────│  (VirusTotal)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌──────────────────┐              │
         └──────────────│  Feature Extract │──────────────┘
                        │     (URL + Net)  │
                        └──────────────────┘
```

## 📊 Technology Stack

- **Backend**: Python 3.8+, Flask
- **Machine Learning**: scikit-learn, Random Forest
- **Data Processing**: pandas, numpy
- **Network Analysis**: dnspython, python-whois, cryptography
- **Threat Intelligence**: VirusTotal v3 API
- **Frontend**: HTML5, CSS3, JavaScript
- **Model Persistence**: joblib

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- Git
- VirusTotal API key (optional but recommended)

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/phishbreaker.git
cd phishbreaker
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment
Create a `config.json` file or set environment variable:
```bash
# Option 1: config.json (in project root)
{
  "VIRUSTOTAL_API_KEY": "your_api_key_here"
}

# Option 2: Environment Variable
export VIRUSTOTAL_API_KEY="your_api_key_here"
```

### 4. Train the Model
```bash
python src/model_train.py
```

### 5. Run the Application
```bash
python app/main.py
```

The application will be available at `http://localhost:5000`

## 🎯 How It Works

### 1. Feature Extraction
The system extracts multiple features from URLs:
- **Basic Features**: URL length, number of dots, hyphens, digits
- **Security Features**: HTTPS usage, IP address usage
- **Content Features**: Presence of banking/payment keywords
- **Network Features**: DNS resolution, domain age, SSL certificate info

### 2. Machine Learning Prediction
- Random Forest classifier with 300 estimators
- Trained on Phishtank dataset
- Handles class imbalance through resampling
- Provides probability scores for phishing detection

### 3. Threat Intelligence Integration
- VirusTotal API integration for URL reputation
- Combines ML probability with VT score
- Weighted scoring (65% ML, 35% VT by default)

### 4. Safe Score Calculation
The system produces a unified safe score (0-100):
- **80-100**: Likely Safe
- **50-79**: Suspicious
- **0-49**: Likely Phishing

## 📁 Project Structure

```
phishbreaker/
├── app/
│   ├── __init__.py
│   ├── main.py              # Flask application
│   ├── static/
│   │   └── style.css        # Web interface styling
│   └── templates/
│       └── index.html       # Main web interface
├── src/
│   ├── __init__.py
│   ├── feature_extraction.py # URL feature extraction
│   ├── model_train.py       # ML model training
│   ├── predict.py           # Core prediction engine
│   ├── reputation.py        # VirusTotal integration
│   ├── utils.py             # Network analysis utilities
│   └── fetch_phishtank.py   # Data collection
├── data/
│   ├── raw/                 # Raw datasets
│   ├── processed/           # Processed features
│   └── logs/                # Prediction logs
├── config.json              # Configuration
├── requirements.txt         # Dependencies
├── phishguard_model.pkl     # Trained ML model
└── README.md               # This file
```

## 🔧 Configuration

### API Configuration
- **VirusTotal API Key**: Obtain from [VirusTotal Community](https://www.virustotal.com/gui/join-us)
- **Prediction Logging**: Enabled by default, logs stored in `data/logs/predictions.csv`
- **Model Threshold**: Default phishing threshold is 0.8 (configurable in `src/predict.py`)

### Model Parameters
```python
# In src/predict.py
phishing_threshold = 0.8  # Adjust sensitivity
weights = (0.65, 0.35)    # ML model vs VirusTotal weight
```

## 📈 Usage Examples

### Web Interface
1. Navigate to `http://localhost:5000`
2. Enter a URL in the input field
3. Click "Check URL"
4. View the prediction result, safe score, and extracted features

### Python API
```python
from src.predict import predict_url

# Basic prediction
result = predict_url("https://example.com/login")
print(f"Label: {result['label']}")
print(f"Safe Score: {result['safe_score']}")
print(f"Model Probability: {result['model_prob']}")

# With custom threshold
result = predict_url("https://suspicious-site.com", phishing_threshold=0.7)
```

## 🔍 API Reference

### `predict_url(url, phishing_threshold=0.8, include_reputation=True)`

**Parameters:**
- `url` (str): URL to analyze
- `phishing_threshold` (float): Threshold for phishing classification (0-1)
- `include_reputation` (bool): Whether to include VirusTotal analysis

**Returns:**
```python
{
  "label": "Phishing" | "Legitimate",
  "model_prob": float or None,      # ML model probability
  "vt": {                           # VirusTotal data
    "vt_score": float,
    "vt_summary": dict,
    "permalink": str
  } or None,
  "safe_score": float,              # 0-100 unified score
  "features": dict                  # Extracted features
}
```

## 🚀 Deployment

### Local Development
```bash
python app/main.py
```

### Production Deployment
For production deployment, consider:
- **Heroku**: Add `Procfile` and `runtime.txt`
- **Railway**: Automatic deployment from GitHub
- **DigitalOcean App Platform**: Managed deployment
- **AWS/GCP**: Containerized deployment with Docker

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Push to the branch: `git push origin feature/new-feature`
5. Submit a pull request

## 📊 Performance

- **Model Accuracy**: Check training output for detailed metrics
- **Response Time**: < 2 seconds for basic analysis
- **Network Features**: Additional 2-5 seconds for comprehensive analysis
- **Throughput**: Supports multiple concurrent requests

## 🛡️ Security Considerations

- API keys stored in environment variables or `config.json`
- Input validation on all user inputs
- Rate limiting recommended for production
- Log sanitization to avoid sensitive data exposure

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Phishtank**: For providing the phishing URL dataset
- **VirusTotal**: For threat intelligence API
- **scikit-learn**: For machine learning framework

## 📞 Support

For support, questions, or feature requests:
- Create an issue in the GitHub repository
- Email: your-email@example.com

## 🔮 Future Enhancements

- [ ] Real-time model retraining
- [ ] Additional threat intelligence sources
- [ ] Browser extension
- [ ] Mobile app
- [ ] Advanced visualization dashboard
- [ ] API rate limiting and authentication

---

**Built with ❤️ for cybersecurity awareness**