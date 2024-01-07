#include <windows.h>

#include <vector>
#include <map>
#include <string>

const char* datatype_names[8] = {
	"void", "int", "float", "coord", "Object", "Unk5", "bool", "float*"
};

char datatype_chars[8] = {
	'n', 'i', 'f', 'c', 'o', 'u', 'b', 'v'
};

std::map<DWORD, std::string> scriptType_names = {
	{1, "script"},
	{2, "help script"},
	{4, "challenge help script"},
	{8, "temple help script"},
	{16, "temple special script"},
	{32, "multiplayer help script"},
};

std::vector<std::string> opcode_keywords[45][3] = {
	/* 0*/	{{"END"}},
	/* 1*/	{{}, {"", "JZ"}, {"", "JZ"}},
	/* 2*/	{{}, {"", "PUSHI", "PUSHF", "PUSHC", "PUSHO", "", "PUSHB", "PUSHV"}, {"", "", "PUSHF", "", "", "", "", "PUSHV"}},
	/* 3*/	{{}, {"", "POPI", "POPF", "", "POPO"}, {"", "", "POPF"}},
	/* 4*/	{{}, {"", "", "ADDF", "ADDC"}},
	/* 5*/	{{}, {"SYS", "", "SYS2"}},
	/* 6*/	{{}, {"", "", "SUBF", "SUBC"}},
	/* 7*/	{{}, {"", "", "NEG"}},
	/* 8*/	{{}, {"", "", "MUL"}},
	/* 9*/	{{}, {"", "", "DIV"}},
	/*10*/	{{}, {"", "", "MOD"}},
	/*11*/	{{}, {"", "NOT"}},
	/*12*/	{{}, {"", "AND"}},
	/*13*/	{{}, {"", "OR"}},
	/*14*/	{{}, {"", "", "EQ"}},
	/*15*/	{{}, {"", "", "NEQ"}},
	/*16*/	{{}, {"", "", "GEQ"}},
	/*17*/	{{}, {"", "", "LEQ"}},
	/*18*/	{{}, {"", "", "GT"}},
	/*19*/	{{}, {"", "", "LT"}},
	/*20*/	{{}, {"", "JMP"}, {"", "JMP"}},
	/*21*/	{{}, {"", "", "SLEEP"}},
	/*22*/	{{}, {"", "EXCEPT"}},
	/*23*/	{{}, {"", "CASTI", "CASTF", "CASTC", "CASTO", "", "CASTB"}},
	/*24*/	{{}, {"", "CALL"}, {"", "START"}},
	/*25*/	{{}, {"", "ENDEXCEPT"}, {"", "FREE"}},
	/*26*/	{{}, {"", "RETEXCEPT"}},
	/*27*/	{{}, {"", "ITEREXCEPT"}},
	/*28*/	{{}, {"", "BRKEXCEPT"}},
	/*29*/	{{}, {"", "SWAP", "SWAPF"}},
	/*30*/	{{"DUP"}},
	/*31*/	{{}, {}, {"", "", "LINE"}},
	/*32*/	{{}, {}, {"", "", "", "", "", "", "", "REF_AND_OFFSET_PUSH"}},
	/*33*/	{{}, {}, {"", "", "REF_AND_OFFSET_POP"}},
	/*34*/	{{}, {"", "", "", "", "", "", "", "REF_PUSH"}, {"", "", "", "", "", "", "", "REF_PUSH2"}},
	/*35*/	{{}, {"", "", "REF_ADD_PUSHF", "", "", "", "", "REF_ADD_PUSHV"}, {"", "", "REF_ADD_PUSHF2", "", "", "", "", "REF_ADD_PUSHV2"}},
	/*36*/	{{"TAN"}},
	/*37*/	{{"SIN"}},
	/*38*/	{{"COS"}},
	/*39*/	{{"ATAN"}},
	/*40*/	{{"ASIN"}},
	/*41*/	{{"ACOS"}},
	/*42*/	{{"ATAN2"}},
	/*43*/	{{"SQRT"}},
	/*44*/	{{"ABS"}}
};

constexpr auto OP_ATTR_ARG = 1;
constexpr auto OP_ATTR_IP = 2 | OP_ATTR_ARG;
constexpr auto OP_ATTR_SCRIPT = 4 | OP_ATTR_ARG;
constexpr auto OP_ATTR_JUMP = 8 | OP_ATTR_ARG | OP_ATTR_IP;
constexpr auto OP_ATTR_FINT = 16;
constexpr auto OP_ATTR_VSTACK = 32;

DWORD opcode_attrs[45] = {
	/* 0*/	0,
	/* 1*/	OP_ATTR_JUMP,
	/* 2*/	OP_ATTR_ARG,
	/* 3*/	OP_ATTR_ARG,
	/* 4*/	OP_ATTR_VSTACK,
	/* 5*/	OP_ATTR_ARG | OP_ATTR_FINT | OP_ATTR_VSTACK,
	/* 6*/	OP_ATTR_VSTACK,
	/* 7*/	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/*20*/	OP_ATTR_JUMP,
	/*21*/	0,
	/*22*/	OP_ATTR_IP,
	/*23*/	0,
	/*24*/	OP_ATTR_SCRIPT | OP_ATTR_VSTACK,
	/*25*/	0, 0, 0, 0,
	/*29*/	OP_ATTR_ARG | OP_ATTR_FINT | OP_ATTR_VSTACK,
	/*30*/	OP_ATTR_ARG,
	/*31*/	OP_ATTR_ARG,
	/*32*/	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

const char* NativeFunctions[] = {
	"NONE", "SET_CAMERA_POSITION", "SET_CAMERA_FOCUS", "MOVE_CAMERA_POSITION", "MOVE_CAMERA_FOCUS", "GET_CAMERA_POSITION", "GET_CAMERA_FOCUS", "SPIRIT_EJECT", "SPIRIT_HOME", "SPIRIT_POINT_POS",
	"SPIRIT_POINT_GAME_THING", "GAME_THING_FIELD_OF_VIEW", "POS_FIELD_OF_VIEW", "RUN_TEXT", "TEMP_TEXT", "TEXT_READ", "GAME_THING_CLICKED", "SET_SCRIPT_STATE", "GET_PROPERTY", "SET_PROPERTY",
	"GET_POSITION", "SET_POSITION", "GET_DISTANCE", "CALL", "CREATE", "RANDOM", "DLL_GETTIME", "START_CAMERA_CONTROL", "END_CAMERA_CONTROL", "SET_WIDESCREEN",
	"MOVE_GAME_THING", "SET_FOCUS", "HAS_CAMERA_ARRIVED", "FLOCK_CREATE", "FLOCK_ATTACH", "FLOCK_DETACH", "FLOCK_DISBAND", "ID_SIZE", "FLOCK_MEMBER", "GET_HAND_POSITION",
	"PLAY_SOUND_EFFECT", "START_MUSIC", "STOP_MUSIC", "ATTACH_MUSIC", "DETACH_MUSIC", "OBJECT_DELETE", "FOCUS_FOLLOW", "POSITION_FOLLOW", "CALL_NEAR", "SPECIAL_EFFECT_POSITION",
	"SPECIAL_EFFECT_OBJECT", "DANCE_CREATE", "CALL_IN", "CHANGE_INNER_OUTER_PROPERTIES", "SNAPSHOT", "GET_ALIGNMENT", "SET_ALIGNMENT", "INFLUENCE_OBJECT", "INFLUENCE_POSITION", "GET_INFLUENCE",
	"SET_INTERFACE_INTERACTION", "PLAYED", "RANDOM_ULONG", "SET_GAMESPEED", "CALL_IN_NEAR", "OVERRIDE_STATE_ANIMATION", "CREATURE_CREATE_RELATIVE_TO_CREATURE", "CREATURE_LEARN_EVERYTHING", "CREATURE_SET_KNOWS_ACTION", "CREATURE_SET_AGENDA_PRIORITY",
	"CREATURE_TURN_OFF_ALL_DESIRES", "CREATURE_LEARN_DISTINCTION_ABOUT_ACTIVITY_OBJECT", "CREATURE_DO_ACTION", "IN_CREATURE_HAND", "CREATURE_SET_DESIRE_VALUE", "CREATURE_SET_DESIRE_ACTIVATED3", "CREATURE_SET_DESIRE_ACTIVATED", "CREATURE_SET_DESIRE_MAXIMUM", "CONVERT_CAMERA_POSITION", "CONVERT_CAMERA_FOCUS",
	"CREATURE_SET_PLAYER", "CREATURE_INITIALISE_NUM_TIMES_PERFORMED_ACTION", "CREATURE_GET_NUM_TIMES_ACTION_PERFORMED", "GET_OBJECT_DROPPED", "CLEAR_DROPPED_BY_OBJECT", "CREATE_REACTION", "REMOVE_REACTION", "GET_COUNTDOWN_TIMER", "START_DUAL_CAMERA", "UPDATE_DUAL_CAMERA",
	"RELEASE_DUAL_CAMERA", "SET_CREATURE_HELP", "GET_TARGET_OBJECT", "CREATURE_DESIRE_IS", "COUNTDOWN_TIMER_EXISTS", "LOOK_GAME_THING", "GET_OBJECT_DESTINATION", "CREATURE_FORCE_FINISH", "GET_ACTION_TEXT_FOR_OBJECT", "CREATE_DUAL_CAMERA_WITH_POINT",
	"SET_CAMERA_TO_FACE_OBJECT", "MOVE_CAMERA_TO_FACE_OBJECT", "GET_MOON_PERCENTAGE", "POPULATE_CONTAINER", "ADD_REFERENCE", "REMOVE_REFERENCE", "SET_GAME_TIME", "GET_GAME_TIME", "GET_REAL_TIME", "GET_REAL_DAY1",
	"GET_REAL_DAY2", "GET_REAL_MONTH", "GET_REAL_YEAR", "RUN_CAMERA_PATH", "START_DIALOGUE", "END_DIALOGUE", "IS_DIALOGUE_READY", "CHANGE_WEATHER_PROPERTIES", "CHANGE_LIGHTNING_PROPERTIES", "CHANGE_TIME_FADE_PROPERTIES",
	"CHANGE_CLOUD_PROPERTIES", "SET_HEADING_AND_SPEED", "START_GAME_SPEED", "END_GAME_SPEED", "BUILD_BUILDING", "SET_AFFECTED_BY_WIND", "WIDESCREEN_TRANSISTION_FINISHED", "GET_RESOURCE", "ADD_RESOURCE", "REMOVE_RESOURCE",
	"GET_TARGET_RELATIVE_POS", "STOP_POINTING", "STOP_LOOKING", "LOOK_AT_POSITION", "PLAY_SPIRIT_ANIM", "CALL_IN_NOT_NEAR", "SET_CAMERA_ZONE", "GET_OBJECT_STATE", "SET_TIMER_TIME", "CREATE_TIMER",
	"GET_TIMER_TIME_REMAINING", "GET_TIMER_TIME_SINCE_SET", "MOVE_MUSIC", "GET_INCLUSION_DISTANCE", "GET_LAND_HEIGHT", "LOAD_MAP", "STOP_ALL_SCRIPTS_EXCLUDING", "STOP_ALL_SCRIPTS_IN_FILES_EXCLUDING", "STOP_SCRIPT", "CLEAR_CLICKED_OBJECT",
	"CLEAR_CLICKED_POSITION", "POSITION_CLICKED", "RELEASE_FROM_SCRIPT", "GET_OBJECT_HAND_IS_OVER", "ID_POISONED_SIZE", "IS_POISONED", "CALL_POISONED_IN", "CALL_NOT_POISONED_IN", "SPIRIT_PLAYED", "CLING_SPIRIT",
	"FLY_SPIRIT", "SET_ID_MOVEABLE", "SET_ID_PICKUPABLE", "IS_ON_FIRE", "IS_FIRE_NEAR", "STOP_SCRIPTS_IN_FILES", "SET_POISONED", "SET_TEMPERATURE", "SET_ON_FIRE", "SET_TARGET",
	"WALK_PATH", "FOCUS_AND_POSITION_FOLLOW", "GET_WALK_PATH_PERCENTAGE", "CAMERA_PROPERTIES", "ENABLE_DISABLE_MUSIC", "GET_MUSIC_OBJ_DISTANCE", "GET_MUSIC_ENUM_DISTANCE", "SET_MUSIC_PLAY_POSITION", "ATTACH_OBJECT_LEASH_TO_OBJECT", "ATTACH_OBJECT_LEASH_TO_HAND",
	"DETACH_OBJECT_LEASH", "SET_CREATURE_ONLY_DESIRE", "SET_CREATURE_ONLY_DESIRE_OFF", "RESTART_MUSIC", "MUSIC_PLAYED1", "IS_OF_TYPE", "CLEAR_HIT_OBJECT", "GAME_THING_HIT", "SPELL_AT_THING", "SPELL_AT_POS",
	"CALL_PLAYER_CREATURE", "GET_SLOWEST_SPEED", "GET_OBJECT_HELD1", "HELP_SYSTEM_ON", "SHAKE_CAMERA", "SET_ANIMATION_MODIFY", "SET_AVI_SEQUENCE", "PLAY_GESTURE", "DEV_FUNCTION", "HAS_MOUSE_WHEEL",
	"NUM_MOUSE_BUTTONS", "SET_CREATURE_DEV_STAGE", "SET_FIXED_CAM_ROTATION", "SWAP_CREATURE", "GET_ARENA", "GET_FOOTBALL_PITCH", "STOP_ALL_GAMES", "ATTACH_TO_GAME", "DETACH_FROM_GAME", "DETACH_UNDEFINED_FROM_GAME",
	"SET_ONLY_FOR_SCRIPTS", "START_MATCH_WITH_REFEREE", "GAME_TEAM_SIZE", "GAME_TYPE", "GAME_SUB_TYPE", "IS_LEASHED", "SET_CREATURE_HOME", "GET_HIT_OBJECT", "GET_OBJECT_WHICH_HIT", "GET_NEAREST_TOWN_OF_PLAYER",
	"SPELL_AT_POINT", "SET_ATTACK_OWN_TOWN", "IS_FIGHTING", "SET_MAGIC_RADIUS", "TEMP_TEXT_WITH_NUMBER", "RUN_TEXT_WITH_NUMBER", "CREATURE_SPELL_REVERSION", "GET_DESIRE", "GET_EVENTS_PER_SECOND", "GET_TIME_SINCE",
	"GET_TOTAL_EVENTS", "UPDATE_SNAPSHOT", "CREATE_REWARD", "CREATE_REWARD_IN_TOWN", "SET_FADE", "SET_FADE_IN", "FADE_FINISHED", "SET_PLAYER_MAGIC", "HAS_PLAYER_MAGIC", "SPIRIT_SPEAKS",
	"BELIEF_FOR_PLAYER", "GET_HELP", "SET_LEASH_WORKS", "LOAD_MY_CREATURE", "OBJECT_RELATIVE_BELIEF", "CREATE_WITH_ANGLE_AND_SCALE", "SET_HELP_SYSTEM", "SET_VIRTUAL_INFLUENCE", "SET_ACTIVE", "THING_VALID",
	"VORTEX_FADE_OUT", "REMOVE_REACTION_OF_TYPE", "CREATURE_LEARN_EVERYTHING_EXCLUDING", "PLAYED_PERCENTAGE", "OBJECT_CAST_BY_OBJECT", "IS_WIND_MAGIC_AT_POS", "CREATE_MIST", "SET_MIST_FADE", "GET_OBJECT_FADE", "PLAY_HAND_DEMO",
	"IS_PLAYING_HAND_DEMO", "GET_ARSE_POSITION", "IS_LEASHED_TO_OBJECT", "GET_INTERACTION_MAGNITUDE", "IS_CREATURE_AVAILABLE", "CREATE_HIGHLIGHT", "GET_OBJECT_HELD2", "GET_ACTION_COUNT", "GET_OBJECT_LEASH_TYPE", "SET_FOCUS_FOLLOW",
	"SET_POSITION_FOLLOW", "SET_FOCUS_AND_POSITION_FOLLOW", "SET_CAMERA_LENS", "MOVE_CAMERA_LENS", "CREATURE_REACTION", "CREATURE_IN_DEV_SCRIPT", "STORE_CAMERA_DETAILS", "RESTORE_CAMERA_DETAILS", "START_ANGLE_SOUND1", "SET_CAMERA_POS_FOC_LENS",
	"MOVE_CAMERA_POS_FOC_LENS", "GAME_TIME_ON_OFF", "MOVE_GAME_TIME", "SET_HIGH_GRAPHICS_DETAIL", "SET_SKELETON", "IS_SKELETON", "PLAYER_SPELL_CAST_TIME", "PLAYER_SPELL_LAST_CAST", "GET_LAST_SPELL_CAST_POS", "ADD_SPOT_VISUAL_TARGET_POS",
	"ADD_SPOT_VISUAL_TARGET_OBJECT", "SET_INDESTRUCTABLE", "SET_GRAPHICS_CLIPPING", "SPIRIT_APPEAR", "SPIRIT_DISAPPEAR", "SET_FOCUS_ON_OBJECT", "RELEASE_OBJECT_FOCUS", "IMMERSION_EXISTS", "SET_DRAW_LEASH", "SET_DRAW_HIGHLIGHT",
	"SET_OPEN_CLOSE", "SET_INTRO_BUILDING", "CREATURE_FORCE_FRIENDS", "MOVE_COMPUTER_PLAYER_POSITION", "ENABLE_DISABLE_COMPUTER_PLAYER1", "GET_COMPUTER_PLAYER_POSITION", "SET_COMPUTER_PLAYER_POSITION", "GET_STORED_CAMERA_POSITION", "GET_STORED_CAMERA_FOCUS", "CALL_NEAR_IN_STATE",
	"SET_CREATURE_SOUND", "CREATURE_INTERACTING_WITH", "SET_SUN_DRAW", "OBJECT_INFO_BITS", "SET_HURT_BY_FIRE", "CONFINED_OBJECT", "CLEAR_CONFINED_OBJECT", "GET_OBJECT_FLOCK", "SET_PLAYER_BELIEF", "PLAY_JC_SPECIAL",
	"IS_PLAYING_JC_SPECIAL", "VORTEX_PARAMETERS", "LOAD_CREATURE", "IS_SPELL_CHARGING", "IS_THAT_SPELL_CHARGING", "OPPOSING_CREATURE", "FLOCK_WITHIN_LIMITS", "HIGHLIGHT_PROPERTIES", "LAST_MUSIC_LINE", "HAND_DEMO_TRIGGER",
	"GET_BELLY_POSITION", "SET_CREATURE_CREED_PROPERTIES", "GAME_THING_CAN_VIEW_CAMERA", "GAME_PLAY_SAY_SOUND_EFFECT", "SET_TOWN_DESIRE_BOOST", "IS_LOCKED_INTERACTION", "SET_CREATURE_NAME", "COMPUTER_PLAYER_READY", "ENABLE_DISABLE_COMPUTER_PLAYER2", "CLEAR_ACTOR_MIND",
	"ENTER_EXIT_CITADEL", "START_ANGLE_SOUND2", "THING_JC_SPECIAL", "MUSIC_PLAYED2", "UPDATE_SNAPSHOT_PICTURE", "STOP_SCRIPTS_IN_FILES_EXCLUDING", "CREATE_RANDOM_VILLAGER_OF_TRIBE", "TOGGLE_LEASH", "GAME_SET_MANA", "SET_MAGIC_PROPERTIES",
	"SET_GAME_SOUND", "SEX_IS_MALE", "GET_FIRST_HELP", "GET_LAST_HELP", "IS_ACTIVE", "SET_BOOKMARK_POSITION", "SET_SCAFFOLD_PROPERTIES", "SET_COMPUTER_PLAYER_PERSONALITY", "SET_COMPUTER_PLAYER_SUPPRESSION", "FORCE_COMPUTER_PLAYER_ACTION",
	"QUEUE_COMPUTER_PLAYER_ACTION", "GET_TOWN_WITH_ID", "SET_DISCIPLE", "RELEASE_COMPUTER_PLAYER", "SET_COMPUTER_PLAYER_SPEED", "SET_FOCUS_FOLLOW_COMPUTER_PLAYER", "SET_POSITION_FOLLOW_COMPUTER_PLAYER", "CALL_COMPUTER_PLAYER", "CALL_BUILDING_IN_TOWN", "SET_CAN_BUILD_WORSHIPSITE",
	"GET_FACING_CAMERA_POSITION", "SET_COMPUTER_PLAYER_ATTITUDE", "GET_COMPUTER_PLAYER_ATTITUDE", "LOAD_COMPUTER_PLAYER_PERSONALITY", "SAVE_COMPUTER_PLAYER_PERSONALITY", "SET_PLAYER_ALLY", "CALL_FLYING", "SET_OBJECT_FADE_IN", "IS_AFFECTED_BY_SPELL", "SET_MAGIC_IN_OBJECT",
	"ID_ADULT_SIZE", "OBJECT_CAPACITY", "OBJECT_ADULT_CAPACITY", "SET_CREATURE_AUTO_FIGHTING", "IS_AUTO_FIGHTING", "SET_CREATURE_QUEUE_FIGHT_MOVE", "SET_CREATURE_QUEUE_FIGHT_SPELL", "SET_CREATURE_QUEUE_FIGHT_STEP", "GET_CREATURE_FIGHT_ACTION", "CREATURE_FIGHT_QUEUE_HITS",
	"GET_PLAYER_ALLY", "SET_PLAYER_WIND_RESISTANCE", "GET_PLAYER_WIND_RESISTANCE", "PAUSE_UNPAUSE_CLIMATE_SYSTEM", "PAUSE_UNPAUSE_STORM_CREATION_IN_CLIMATE_SYSTEM", "GET_MANA_FOR_SPELL", "KILL_STORMS_IN_AREA", "INSIDE_TEMPLE", "RESTART_OBJECT", "SET_GAME_TIME_PROPERTIES",
	"RESET_GAME_TIME_PROPERTIES", "SOUND_EXISTS", "GET_TOWN_WORSHIP_DEATHS", "GAME_CLEAR_DIALOGUE", "GAME_CLOSE_DIALOGUE", "GET_HAND_STATE", "SET_INTERFACE_CITADEL", "MAP_SCRIPT_FUNCTION", "WITHIN_ROTATION", "GET_PLAYER_TOWN_TOTAL",
	"SPIRIT_SCREEN_POINT", "KEY_DOWN", "SET_FIGHT_CAMERA_EXIT", "GET_OBJECT_CLICKED", "GET_MANA", "CLEAR_PLAYER_SPELL_CHARGING", "STOP_SOUND_EFFECT", "GET_TOTEM_STATUE", "SET_SET_ON_FIRE", "SET_LAND_BALANCE",
	"SET_OBJECT_BELIEF_SCALE", "START_IMMERSION", "STOP_IMMERSION", "STOP_ALL_IMMERSION", "SET_CREATURE_IN_TEMPLE", "GAME_DRAW_TEXT", "GAME_DRAW_TEMP_TEXT", "FADE_ALL_DRAW_TEXT", "SET_DRAW_TEXT_COLOUR", "SET_CLIPPING_WINDOW",
	"CLEAR_CLIPPING_WINDOW", "SAVE_GAME_IN_SLOT", "SET_OBJECT_CARRYING", "POS_VALID_FOR_CREATURE", "GET_TIME_SINCE_OBJECT_ATTACKED", "GET_TOWN_AND_VILLAGER_HEALTH_TOTAL", "GAME_ADD_FOR_BUILDING", "ENABLE_DISABLE_ALIGNMENT_MUSIC", "GET_DEAD_LIVING", "ATTACH_SOUND_TAG",
	"DETACH_SOUND_TAG", "GET_SACRIFICE_TOTAL", "GAME_SOUND_PLAYING", "GET_TEMPLE_POSITION", "CREATURE_AUTOSCALE", "GET_SPELL_ICON_IN_TEMPLE", "GAME_CLEAR_COMPUTER_PLAYER_ACTIONS", "GET_FIRST_IN_CONTAINER", "GET_NEXT_IN_CONTAINER", "GET_TEMPLE_ENTRANCE_POSITION",
	"SAY_SOUND_EFFECT_PLAYING", "SET_HAND_DEMO_KEYS", "CAN_SKIP_TUTORIAL", "CAN_SKIP_CREATURE_TRAINING", "IS_KEEPING_OLD_CREATURE", "CURRENT_PROFILE_HAS_CREATURE", "THING_PLAY_ANIM", "SET_SCRIPT_STATE_WITH_PARAMS", "START_COUNTDOWN_TIMER", "END_COUNTDOWN_TIMER",
	"SET_COUNTDOWN_TIMER_DRAW", "SET_OBJECT_SCORE", "GET_OBJECT_SCORE", "SET_CREATURE_FOLLOW_MASTER", "SET_CREATURE_DISTANCE_FROM_HOME", "GAME_DELETE_FIRE", "GET_OBJECT_EP", "GET_COUNTDOWN_TIMER_TIME", "SET_OBJECT_IN_PLAYER_HAND", "CREATE_PLAYER_TEMPLE",
	"START_CANNON_CAMERA", "END_CANNON_CAMERA", "GET_LANDING_POS", "SET_CREATURE_MASTER", "SET_CANNON_PERCENTAGE", "SET_DIE_ROLL_CHECK", "SET_CAMERA_HEADING_FOLLOW", "SET_CANNON_STRENGTH", "GAME_CREATE_TOWN", "SET_OBJECT_NAVIGATION",
	"DO_ACTION_AT_POS", "GET_OBJECT_DESIRE", "GET_CREATURE_CURRENT_ACTION", "GET_CREATURE_SPELL_SKILL", "GET_CREATURE_KNOWS_ACTION", "CALL_BUILDING_WOODPILE_IN_TOWN", "GET_MOUSE_ACROSS", "GET_MOUSE_DOWN", "SET_DOLPHIN_MOVE", "MOUSE_DOWN",
	"IN_WIDESCREEN", "AFFECTED_BY_SNOW", "SET_DOLPHIN_SPEED", "SET_DOLPHIN_WAIT", "FIRE_GUN", "GUN_ANGLE_PITCH", "SET_OBJECT_TATTOO", "CREATURE_CLEAR_FIGHT_QUEUE", "CAN_BE_LEASHED", "SET_BOOKMARK_ON_OBJECT",
	"SET_OBJECT_LIGHTBULB", "SET_CREATURE_CAN_DROP", "PLAY_SPIRIT_ANIM_IN_WORLD", "SET_OBJECT_COLOUR", "EFFECT_FROM_FILE", "ALEX_SPECIAL_EFFECT_POSITION", "DELETE_FRAGMENTS_IN_RADIUS", "DELETE_FRAGMENTS_FOR_OBJECT", "SET_CAMERA_AUTO_TRACK", "CREATURE_HELP_ON",
	"CREATURE_CAN_LEARN", "GET_OBJECT_HAND_POSITION", "CREATURE_SET_RIGHT_HAND_ONLY", "GAME_HOLD_WIDESCREEN", "CREATURE_CREATE_YOUNG_WITH_KNOWLEDGE", "STOP_DIALOGUE_SOUND", "GAME_THING_HIT_LAND", "GET_LAST_OBJECT_WHICH_HIT_LAND", "CLEAR_HIT_LAND_OBJECT", "SET_DRAW_SCOREBOARD",
	"GET_BRACELET_POSITION", "SET_FIGHT_LOCK", "SET_VILLAGER_SOUND", "CLEAR_SPELLS_ON_OBJECT", "ENABLE_OBJECT_IMMUNE_TO_SPELLS", "IS_OBJECT_IMMUNE_TO_SPELLS", "GET_OBJECT_OBJECT_LEASHED_TO", "SET_FIGHT_QUEUE_ONLY",
	NULL
};