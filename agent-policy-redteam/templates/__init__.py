from templates.data_exfiltration import TEMPLATE_PROMPT as DATA_EXFILTRATION_TEMPLATE
from templates.unauthorized_action import TEMPLATE_PROMPT as UNAUTHORIZED_ACTION_TEMPLATE
from templates.data_corruption import TEMPLATE_PROMPT as DATA_CORRUPTION_TEMPLATE

TEMPLATES = {
    "data_exfiltration": DATA_EXFILTRATION_TEMPLATE,
    "unauthorized_action": UNAUTHORIZED_ACTION_TEMPLATE,
    "data_corruption": DATA_CORRUPTION_TEMPLATE,
}
