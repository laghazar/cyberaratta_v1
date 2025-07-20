from django.shortcuts import render, redirect, get_object_or_404
from .models import QuizCategory, Question, Answer, QuizSession, QuizResult, QuizAttempt
from django.http import JsonResponse, Http404
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.db import transaction
import json
import random
import logging

logger = logging.getLogger(__name__)


def validate_session_access(request, session_id):
    """Validate that the user has access to the given quiz session."""
    try:
        session = get_object_or_404(QuizSession, id=session_id)
        stored_session_id = request.session.get('quiz_session_id')
        
        if stored_session_id != session.id:
            logger.warning(f"Unauthorized session access attempt: {session_id} by session {request.session.session_key}")
            raise Http404("Անհրաժեշտ քուիզի նիստը չի գտնվել:")
        
        return session
    except QuizSession.DoesNotExist:
        logger.error(f"Quiz session not found: {session_id}")
        raise Http404("Քուիզի նիստը չի գտնվել:")


def get_optimized_questions(category, question_type):
    """Get optimized questions query with select_related."""
    return Question.objects.select_related('category').filter(
        category=category, 
        question_type=question_type, 
        is_active=True
    ).order_by('id')


def calculate_character_result(percentage):
    """Calculate character result based on percentage with improved logic."""
    if percentage >= 90:
        return "ara", "Դու անտուն կիբեռգիտակ ես! Արա Գեղեցիկի կողմնակից ես:"
    elif percentage >= 70:
        return "ara", "Դու Արա Գեղեցիկի կողմնակից ես, դու կիբեռգիտակ ես:"
    elif percentage >= 50:
        return "shamiram", "Դու լավ գիտելիք ունես, բայց ավելի շատ սովորի՛ր:"
    else:
        return "shamiram", "Դու Շամիրամի կողմնակից ես, պահպանի՛ր զգոնություն, սովորի՛ր ավելին:"

def quiz_home(request):
    """Display quiz home page with available categories."""
    try:
        categories = QuizCategory.objects.filter(is_active=True)
        return render(request, 'quiz/home.html', {
            'categories': categories, 
            'Question': Question
        })
    except Exception as e:
        logger.error(f"Error in quiz_home: {str(e)}")
        messages.error(request, "Խնդիր է առաջացել քուիզները բեռնելիս:")
        return render(request, 'quiz/home.html', {
            'categories': [], 
            'Question': Question
        })

@require_http_methods(["GET", "POST"])
def start_quiz(request):
    """Start a new quiz session."""
    try:
        if request.method == 'POST':
            category_id = request.POST.get('category')
            question_type = request.POST.get('question_type')
            
            # Input validation
            if not category_id or not question_type:
                messages.error(request, "Անհրաժեշտ է ընտրել կատեգորիա և հարցի տեսակ:")
                return redirect('quiz:start_quiz')
            
            try:
                category = get_object_or_404(QuizCategory, id=category_id, is_active=True)
            except Http404:
                messages.error(request, "Ընտրված կատեգորիան չի գտնվել:")
                return redirect('quiz:start_quiz')
            
            # Validate question_type
            valid_types = [choice[0] for choice in Question.QUESTION_TYPES]
            if question_type not in valid_types:
                messages.error(request, "Անհրաժեշտ հարցի տեսակ:")
                return redirect('quiz:start_quiz')
            
            questions = get_optimized_questions(category, question_type)
            if not questions.exists():
                messages.error(request, "Ընտրված կատեգորիայի համար հարցեր չկան:")
                return redirect('quiz:start_quiz')
            
            # Create session with better session key generation
            with transaction.atomic():
                session = QuizSession.objects.create(
                    session_key=f"{random.randint(100000, 999999)}-{category.id}",
                    category=category,
                    question_type=question_type,
                    current_question=0,
                    score=0,
                )
                request.session['quiz_session_id'] = session.id
                logger.info(f"New quiz session created: {session.id} for category: {category.name}")
            
            return redirect('quiz:quiz_question', session.id)
        
        # GET request
        categories = QuizCategory.objects.filter(is_active=True)
        return render(request, 'quiz/start.html', {
            'categories': categories, 
            'Question': Question
        })
        
    except Exception as e:
        logger.error(f"Error in start_quiz: {str(e)}")
        messages.error(request, "Խնդիր է առաջացել քուիզը սկսելիս:")
        categories = QuizCategory.objects.filter(is_active=True)
        return render(request, 'quiz/start.html', {
            'categories': categories, 
            'Question': Question
        })

def quiz_question(request, session_id):
    """Display current quiz question."""
    try:
        session = validate_session_access(request, session_id)
        questions = get_optimized_questions(session.category, session.question_type)
        total_questions = questions.count()
        
        if session.current_question >= total_questions:
            return redirect('quiz:quiz_result', session.id)
        
        question = questions[session.current_question]
        answers = question.answers.all()
        progress = int((session.current_question + 1) / total_questions * 100)
        
        return render(request, f'quiz/{session.question_type}.html', {
            'session': session,
            'question': question,
            'answers': answers,
            'question_number': session.current_question + 1,
            'total_questions': total_questions,
            'progress': progress,
        })
        
    except Http404:
        raise
    except Exception as e:
        logger.error(f"Error in quiz_question: {str(e)}")
        messages.error(request, "Խնդիր է առաջացել հարցը բեռնելիս:")
        return redirect('quiz:home')

@require_http_methods(["POST"])
def submit_answer(request, session_id):
    """Submit answer for current question and track attempt."""
    try:
        session = validate_session_access(request, session_id)
        questions = get_optimized_questions(session.category, session.question_type)
        total_questions = questions.count()
        
        if session.current_question >= total_questions:
            return JsonResponse({
                'error': 'Քուիզն արդեն ավարտված է:',
                'redirect': f'/quiz/result/{session.id}/'
            }, status=400)
        
        question = questions[session.current_question]
        
        # Handle both regular POST and JSON requests
        if request.content_type == 'application/json':
            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Անվավեր JSON ֆորմատ:'}, status=400)
        else:
            data = request.POST
        
        answer_id = data.get('answer_id')
        
        # Input validation
        if not answer_id:
            return JsonResponse({'error': 'Անհրաժեշտ է ընտրել պատասխան:'}, status=400)
        
        try:
            answer_id = int(answer_id)
            answer = get_object_or_404(Answer, id=answer_id, question=question)
        except (ValueError, TypeError):
            return JsonResponse({'error': 'Անվավեր պատասխանի ID:'}, status=400)
        except Http404:
            return JsonResponse({'error': 'Ընտրված պատասխանը չի գտնվել:'}, status=404)
        
        correct = answer.is_correct
        points_earned = question.points if correct else 0
        
        # Create QuizAttempt with transaction
        with transaction.atomic():
            # Create attempt record
            QuizAttempt.objects.create(
                session=session,
                question=question,
                answer=answer,
                is_correct=correct
            )
            
            # Update session
            session.score += points_earned
            session.current_question += 1
            session.save()
        
        logger.info(f"Answer submitted for session {session.id}, question {question.id}, correct: {correct}")
        
        return JsonResponse({
            'correct': correct,
            'explanation': question.explanation or '',
            'points_earned': points_earned,
            'current_score': session.score,
            'next_question': session.current_question < total_questions
        })
        
    except Http404:
        return JsonResponse({'error': 'Նիստը չի գտնվել:'}, status=404)
    except Exception as e:
        logger.error(f"Error in submit_answer: {str(e)}")
        return JsonResponse({'error': 'Սերվերի սխալ:'}, status=500)

def quiz_result(request, session_id):
    """Display quiz results."""
    try:
        session = validate_session_access(request, session_id)
        questions = get_optimized_questions(session.category, session.question_type)
        total_score = questions.count() * 10  # Assuming 10 points per question
        percentage = int((session.score / total_score) * 100) if total_score else 0
        
        character_result, feedback_message = calculate_character_result(percentage)
        
        # Mark session as completed and create/get result
        with transaction.atomic():
            session.is_completed = True
            session.save()
            
            result, created = QuizResult.objects.get_or_create(
                session=session,
                defaults={
                    'final_score': session.score,
                    'percentage': percentage,
                    'character_result': character_result,
                    'feedback_message': feedback_message
                }
            )
        
        # Get quiz attempts for detailed analytics
        attempts = QuizAttempt.objects.select_related('question', 'answer').filter(
            session=session
        ).order_by('attempted_at')
        
        # Calculate additional statistics
        correct_answers = attempts.filter(is_correct=True).count()
        total_attempts = attempts.count()
        
        # Clear session data for security
        if 'quiz_session_id' in request.session:
            del request.session['quiz_session_id']
        
        logger.info(f"Quiz completed for session {session.id}, score: {session.score}, percentage: {percentage}%")
        
        return render(request, 'quiz/result.html', {
            'result': result,
            'session': session,
            'attempts': attempts,
            'correct_answers': correct_answers,
            'total_attempts': total_attempts,
            'total_questions': questions.count(),
        })
        
    except Http404:
        raise
    except Exception as e:
        logger.error(f"Error in quiz_result: {str(e)}")
        messages.error(request, "Խնդիր է առաջացել արդյունքները բեռնելիս:")
        return redirect('quiz:home')
    