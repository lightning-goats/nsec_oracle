from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from lnbits.core.models import User
from lnbits.decorators import check_user_exists
from lnbits.helpers import template_renderer

nsec_oracle_generic_router = APIRouter()


def nsec_oracle_renderer():
    return template_renderer(["nsec_oracle/templates"])


@nsec_oracle_generic_router.get("/", response_class=HTMLResponse)
async def index(request: Request, user: User = Depends(check_user_exists)):
    return nsec_oracle_renderer().TemplateResponse(
        "nsec_oracle/index.html", {"request": request, "user": user.json()}
    )
