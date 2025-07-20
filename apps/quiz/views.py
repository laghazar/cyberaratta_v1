from django.shortcuts import render, redirect, get_object_or_404
from .models import QuizCategory, Question, Answer, QuizSession, QuizResult, QuizAttempt
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import random

def quiz_home(request):
    categories = QuizCategory.objects.filter(is_active=True)
    return render(request, 'quiz/home.html', {'categories': categories, 'Question': Question})

def start_quiz(request):
    if request.method == 'POST':
        category_id = request.POST.get('category')
        question_type = request.POST.get('question_type')
        category = get_object_or_404(QuizCategory, id=category_id)
        questions = Question.objects.filter(category=category, question_type=question_type, is_active=True)
        
        if not questions.exists():
            return render(request, 'quiz/home.html', {
                'categories': QuizCategory.objects.filter(is_active=True), 
                'Question': Question, 
                'error': 'Հարցեր չկան այս կատեգորիայում։'
            })
            
        session = QuizSession.objects.create(
            session_key=str(random.randint(1000000,9999999)),
            category=category,
            question_type=question_type,
            current_question=0,
            score=0,
        )
        request.session['quiz_session_id'] = session.id
        return redirect('quiz:quiz_question', session.id)
    
    # This should never execute as we're using the home page for selection now
    return redirect('quiz:home')

def quiz_question(request, session_id):
    session = get_object_or_404(QuizSession, id=session_id)
    
    # If session is completed, redirect to results
    if session.is_completed:
        return redirect('quiz:quiz_result', session.id)
    
    questions = Question.objects.filter(
        category=session.category, 
        question_type=session.question_type, 
        is_active=True
    ).order_by('difficulty')
    
    total_questions = questions.count()
    
    # If we've gone through all questions, mark as completed and redirect to results
    if session.current_question >= total_questions:
        session.is_completed = True
        session.save()
        return redirect('quiz:quiz_result', session.id)
    
    question = questions[session.current_question]
    answers = list(question.answers.all())
    random.shuffle(answers)  # Shuffle answers for more variety
    
    progress = int((session.current_question + 1) / total_questions * 100)
    
    # Use the appropriate template based on question type
    template_name = f'quiz/{session.question_type}.html'
    
    return render(request, template_name, {
        'session': session,
        'question': question,
        'answers': answers,
        'question_number': session.current_question + 1,
        'total_questions': total_questions,
        'progress': progress,
    })

@csrf_exempt
def submit_answer(request, session_id):
    session = get_object_or_404(QuizSession, id=session_id)
    
    # If session is completed, return error
    if session.is_completed:
        return JsonResponse({'error': 'Quiz already completed'}, status=400)
    
    questions = Question.objects.filter(
        category=session.category, 
        question_type=session.question_type, 
        is_active=True
    ).order_by('difficulty')
    
    total_questions = questions.count()
    
    # If we've gone through all questions, mark as completed
    if session.current_question >= total_questions:
        session.is_completed = True
        session.save()
        return JsonResponse({'redirect': 'result'})
    
    question = questions[session.current_question]
    
    # Parse data from request
    data = request.POST or request.body
    if isinstance(data, bytes):
        import json
        data = json.loads(data)
    
    answer_id = data.get('answer_id')
    if not answer_id:
        return JsonResponse({'error': 'No answer provided'}, status=400)
    
    answer = get_object_or_404(Answer, id=answer_id)
    correct = answer.is_correct
    
    # Calculate points based on answer correctness and difficulty
    points_earned = question.points if correct else 0
    
    # Record the quiz attempt
    QuizAttempt.objects.create(
        session=session,
        question=question,
        answer=answer,
        is_correct=correct
    )
    
    # Update session score and move to next question
    session.score += points_earned
    session.current_question += 1
    session.save()
    
    # Check if this was the last question
    if session.current_question >= total_questions:
        session.is_completed = True
        session.save()
    
    return JsonResponse({
        'correct': correct,
        'explanation': question.explanation,
        'points_earned': points_earned,
    })

def quiz_result(request, session_id):
    session = get_object_or_404(QuizSession, id=session_id)
    questions = Question.objects.filter(
        category=session.category, 
        question_type=session.question_type, 
        is_active=True
    )
    
    # Calculate total possible score
    total_possible_score = sum(question.points for question in questions)
    
    # Calculate percentage
    percentage = int((session.score / total_possible_score) * 100) if total_possible_score else 0
    
    # Determine character result based on score
    character_result = "ara" if percentage >= 70 else "shamiram"
    
    # Customize feedback based on result
    if character_result == "ara":
        feedback_message = "Շնորհավորում ենք! Դուք Արա Գեղեցիկի կողմնակից եք: Դուք ունեք կիբեռանվտանգության բարձր գիտելիքներ և կարող եք հաջողությամբ պաշտպանվել կիբեռսպառնալիքներից։"
    else:
        feedback_message = "Դուք Շամիրամի կողմնակից եք: Պահպանեք զգոնությունը և շարունակեք զարգացնել ձեր կիբեռանվտանգության հմտությունները։ Ուսումնասիրեք մեր նյութերը ավելի շատ գիտելիքների համար։"
    
    # Create or get result
    result, created = QuizResult.objects.get_or_create(
        session=session,
        defaults={
            'final_score': session.score,
            'percentage': percentage,
            'character_result': character_result,
            'feedback_message': feedback_message
        }
    )
    
    return render(request, 'quiz/result.html', {
        'result': result,
        'session': session,
        'total_possible_score': total_possible_score,
    })
    
def leaderboard(request):
    results = QuizResult.objects.filter(is_visible=True).order_by('-percentage', '-final_score')[:10]
    return render(request, 'quiz/leaderboard.html', {'results': results})