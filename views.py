from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from lnbits.core.models import User
from lnbits.decorators import check_user_exists
from lnbits.helpers import template_renderer

nsecbunker_generic_router = APIRouter()


def nsecbunker_renderer():
    return template_renderer(["nsecbunker/templates"])


@nsecbunker_generic_router.get("/", response_class=HTMLResponse)
async def index(request: Request, user: User = Depends(check_user_exists)):
    return nsecbunker_renderer().TemplateResponse(
        "nsecbunker/index.html", {"request": request, "user": user.json()}
    )
