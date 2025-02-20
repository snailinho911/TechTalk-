from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import Request

from database import SessionLocal, engine
from models import Base, User, Article

# Создаем таблицы (если не существуют)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="TechTalk Hub")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# ---- JWT Settings ----
SECRET_KEY = "SUPER_SECRET_KEY"  # В реальном проекте храните в .env
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)


# ---- PassLib для хэширования паролей ----
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


# ---- Функции JWT ----
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Создаёт JWT-токен с дополнительными данными (data) и временем жизни.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# ---- Зависимость для получения DB-сессии ----
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_current_user_from_cookie(
    request: Request,
    db: Session = Depends(get_db)
):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            return None
    except JWTError:
        return None
    user = db.query(User).filter(User.id == user_id).first()
    return user

# ---- Зависимость для проверки JWT и получения текущего пользователя ----
async def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    """
    Извлекает user_id из JWT-токена, находит пользователя в БД и возвращает его.
    Если токен недействителен или пользователь не найден — выбрасывает ошибку.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user


# ====== Стандартные страницы ======

@app.get("/", response_class=HTMLResponse)
async def read_root(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_from_cookie)
):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "Главная",
        "current_user": current_user
    })

@app.get("/about", response_class=HTMLResponse)
async def about(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_from_cookie)
):
    return templates.TemplateResponse("about.html", {
        "request": request,
        "title": "О сайте",
        "current_user": current_user
    })


@app.get("/contact", response_class=HTMLResponse)
async def contact(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_from_cookie)
):
    return templates.TemplateResponse("contact.html", {
        "request": request,
        "title": "Контакты",
        "current_user": current_user
    })

@app.post("/contact", response_class=HTMLResponse)
async def contact_post(request: Request, name: str = Form(...),current_user: Optional[User] = Depends(get_current_user_from_cookie)):
    return templates.TemplateResponse("thank_you.html", {"request": request, "name": name, "current_user": current_user})



async def get_current_user_optional(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    if token is None:
        return None
    try:
        return await get_current_user(token, db)
    except HTTPException:
        return None



@app.get("/blog", response_class=HTMLResponse)
async def blog(
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_from_cookie)
):
    articles = db.query(Article).all()
    return templates.TemplateResponse("blog.html", {
        "request": request,
        "title": "Статьи",
        "articles": articles,
        "current_user": current_user
    })




@app.get("/counters", response_class=HTMLResponse)
async def counters(request: Request, current_user: Optional[User] = Depends(get_current_user_from_cookie)):
    return templates.TemplateResponse("counters.html", {"request": request, "title": "Счетчики", "current_user": current_user})


# ====== Авторизация с JWT ======

@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,  # добавляем этот параметр первым
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Обработчик логина: принимает данные из формы,
    проверяет учетные данные, создает JWT и устанавливает его в cookie,
    затем перенаправляет пользователя на главную страницу.
    Если данные неверные, возвращает форму логина с сообщением об ошибке.
    """
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        error = "Неверное имя пользователя или пароль"
        return templates.TemplateResponse("login.html", {
            "request": request,
            "title": "Авторизация",
            "error": error
        })
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=access_token_expires
    )
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response






@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    """
    Пример HTML-формы для логина (через username/password).
    Но сам токен вернётся в JSON-ответе (по спецификации OAuth2).
    """
    return templates.TemplateResponse("login.html", {"request": request, "title": "Авторизация"})


# ====== Регистрация ======

@app.get("/register", response_class=HTMLResponse)
async def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "title": "Регистрация"})


@app.post("/register", response_class=HTMLResponse)
async def register_post(
        request: Request,
        username: str = Form(...),
        email: str = Form(...),
        password: str = Form(...),
        db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        error = "Пользователь с таким именем уже существует"
        return templates.TemplateResponse("register.html", {"request": request, "title": "Регистрация", "error": error})

    hashed_password = get_password_hash(password)
    new_user = User(username=username, email=email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return templates.TemplateResponse("index.html",
                                      {"request": request, "title": "Регистрация", "username": username})


# ====== Работа со статьями ======




@app.get("/blog/create", response_class=HTMLResponse)
async def create_article_get(request: Request,current_user: User = Depends(get_current_user_from_cookie)):

    return templates.TemplateResponse("create_article.html", {"request": request, "title": "Создать статью", "current_user": current_user})


@app.post("/blog/create", response_class=HTMLResponse)
async def create_article_post(
        request: Request,
        title: str = Form(...),
        content: str = Form(...),
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user_from_cookie)  # Требует JWT-токен
):
    """
    Сохранение статьи. Защищённая операция: нужен валидный JWT-токен.
    current_user определяется через get_current_user (JWT).
    """
    new_article = Article(
        title=title,
        content=content,
        author_id=current_user.id
    )
    db.add(new_article)
    db.commit()
    db.refresh(new_article)

    return templates.TemplateResponse("create_article_success.html", {
        "request": request,
        "title": "Статья создана",
        "article": new_article
    })

@app.get("/blog/{article_id}", response_class=HTMLResponse)
async def article_detail(
    article_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_from_cookie)
):
    article = db.query(Article).filter(Article.id == article_id).first()
    if not article:
        raise HTTPException(status_code=404, detail="Статья не найдена")
    return templates.TemplateResponse("article_detail.html", {
        "request": request,
        "title": article.title,
        "article": article,
        "current_user": current_user
    })


@app.get("/logout", response_class=HTMLResponse)
async def logout(request: Request):
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("access_token")
    return response
