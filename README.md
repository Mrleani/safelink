# SafeLink API

FastAPI ბექენდი SafeLink-ისთვის.

## ლოკალურად გაშვება
```
pip install -r requirements.txt
uvicorn main:app --reload
```
შემოწმება: `curl -X POST localhost:8000/api/check -H "Content-Type: application/json" -d '{"text":"bog-ge.com/verify"}'`

## Render-ზე ატვირთვა (უფასო)
1. ატვირთე ეს საქაღალდე GitHub-ზე.
2. Render → New → Blueprint (ან Web Service) → აირჩიე რეპო. `render.yaml` ყველაფერს თვითონ მოარგებს.
3. ატვირთვის მერე ფრონტში `const API_BASE = "https://შენი-სერვისი.onrender.com";`
4. რეკომენდებული: `ALLOWED_ORIGINS`-ში ჩაწერე შენი ფრონტის დომენი `*`-ის ნაცვლად.

## ფრონტის ერთად გაშვება (არჩევითი)
ფრონტის ფაილი შეინახე `static/index.html`-ად და `API_BASE`-ად ჩაწერე `location.origin`.
მაშინ ერთი Render სერვისი ორივეს მოემსახურება.

## არჩევითი გაუმჯობესება
`GSB_API_KEY` — უფასო Google Safe Browsing გასაღები, ბაზაში შემოწმებისთვის.

## შენიშვნები
- Render-ის უფასო გეგმა ~15 წუთის უმოქმედობის მერე იძინებს, პირველი მოთხოვნა ~30 წამს გასტანს (ფრონტს 12 წამის timeout აქვს და დემოზე გადადის, ამიტომ შეგიძლია UptimeRobot-ით ყოველ 10 წუთში `/api/health`-ს დაუძახო).
- უფასო დისკი დროებითია: `reports.db` ხელახალი დეპლოისას იშლება.
- `/api/report` სრულ ტექსტს არ ინახავს, მხოლოდ დომენებს და ჰეშს, ფრონტის „ტექსტს არ ვინახავთ“ დაპირების შესაბამისად.
